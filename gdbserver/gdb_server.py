"""?
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

import logging, threading, socket
import colorlog

from struct import unpack
from time import sleep, time
from sys import stdout

from protocol import Socket, WebSocket

#from pyOCD.target.target import TARGET_HALTED, WATCHPOINT_READ, WATCHPOINT_WRITE, WATCHPOINT_READ_WRITE
from utility import hexStringToIntList, hexEncode, hexDecode



# Logging options. Set to True to enable.
LOG_MEM = True # Log memory accesses.
LOG_ACK = False # Log ack or nak.


class TransferError(ValueError):
    pass


class GDBServer(threading.Thread):
    """
    This class start a GDB server listening a gdb connection on a specific port.
    It implements the RSP (Remote Serial Protocol).
    """

    def __init__(self, board, options = {}):

        log_format = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"

        #logging.basicConfig(level=log_level)

        handler = logging.StreamHandler()
        handler.setLevel(options.get('log_level'))
        handler.setFormatter(colorlog.ColoredFormatter(log_format))

        self.logger = colorlog.getLogger(type(self).__name__)
        self.logger.setLevel(options.get('log_level'))
        self.logger.addHandler(handler)


        threading.Thread.__init__(self)

        # Initialize the board with the respective target.
        self.board = board
        self.target = board.target

        #self.flash = board.flash
        self.abstract_socket = None
        self.wss_server = None
        self.port = 0

        port_urlWSS = options.get('port_urlWSS')

        if isinstance(port_urlWSS, str) == True:
            self.wss_server = port_urlWSS
        else:
            self.port = port_urlWSS

        self.break_at_hardfault = bool(options.get('break_at_hardfault', True))
        # XXX : is this needed?
        #self.board.target.setVectorCatchFault(self.break_at_hardfault)
        self.break_on_reset = options.get('break_on_reset', False)
        #self.board.target.setVectorCatchReset(self.break_on_reset)
        self.step_into_interrupt = options.get('step_into_interrupt', False)
        self.persist = options.get('persist', False)
        self.soft_bkpt_as_hard = options.get('soft_bkpt_as_hard', False)
        self.chip_erase = options.get('chip_erase', None)
        self.hide_programming_progress = options.get('hide_programming_progress', False)
        self.fast_program = options.get('fast_program', False)

        self.packet_size = 2048
        self.send_acks = True
        self.clear_send_acks = False
        self.gdb_features = []

        self.flashBuilder = None # XXX delete
        self.conn = None
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.detach_event = threading.Event()
        self.quit = False

        if self.wss_server == None:
            self.abstract_socket = Socket(self.port, self.packet_size)
        else:
            self.abstract_socket = WebSocket(self.wss_server)
        self.setDaemon(True)
        self.start()

    def restart(self):
        if self.isAlive():
            self.detach_event.set()

    def stop(self):
        if self.isAlive():
            self.shutdown_event.set()
            while self.isAlive():
                pass
            self.logger.info("GDB server thread killed")
        #self.board.uninit()

    def setBoard(self, board, stop = True):
        self.lock.acquire()
        if stop:
            self.restart()
        self.board = board
        self.target = board.target
        self.flash = board.flash
        self.lock.release()
        return

    def run(self):
        self.timeOfLastPacket = time()
        while True:
            new_command = False
            data = ""
            self.logger.info('GDB server started at port:%d',self.port)

            self.shutdown_event.clear()
            self.detach_event.clear()

            while not self.shutdown_event.isSet() and not self.detach_event.isSet():
                connected = self.abstract_socket.connect()
                if connected != None:
                    break

            if self.shutdown_event.isSet():
                return

            if self.detach_event.isSet():
                continue

            self.logger.info("One client connected!")

            self.logger.info("Starting emulator...")
            self.target.init()

            while True:

                if self.shutdown_event.isSet():
                    return

                if self.detach_event.isSet():
                    continue

                # read command
                while True:
                    if (new_command == True):
                        new_command = False
                        break

                    # Reduce CPU usage by sleep()ing once we know that the
                    # debugger doesn't have a queue of commands that we should
                    # execute as quickly as possible.
                    if time() - self.timeOfLastPacket > 0.5:
                        sleep(0.1)
                    try:
                        if self.shutdown_event.isSet() or self.detach_event.isSet():
                            break
                        self.abstract_socket.setBlocking(0)
                        data += self.abstract_socket.read()
                        if data.index("$") >= 0 and data.index("#") >= 0:
                            break
                    except (ValueError, socket.error):
                        pass

                if self.shutdown_event.isSet():
                    return

                if self.detach_event.isSet():
                    continue

                self.abstract_socket.setBlocking(1)

                data = data[data.index("$"):]

                self.lock.acquire()

                if len(data) != 0:
                    # decode and prepare resp
                    [resp, ack, detach] = self.handleMsg(data)

                    # Clear out data
                    data = ""

                    if resp is not None:
                        # ack
                        if ack and self.send_acks:
                            resp = "+" + resp
                        # send resp
                        self.abstract_socket.write(resp)
                        if self.send_acks:
                            # wait a '+' from the client
                            try:
                                data = self.abstract_socket.read()
                                if LOG_ACK:
                                    if data[0] != '+':
                                        self.logger.debug('gdb client has not ack!')
                                    else:
                                        self.logger.debug('gdb client has ack!')
                                if self.clear_send_acks:
                                    self.send_acks = False
                                if data.index("$") >= 0 and data.index("#") >= 0:
                                    new_command = True
                            except:
                                pass

                    if detach:
                        self.abstract_socket.close()
                        self.lock.release()
                        if self.persist:
                            break
                        else:
                            return

                    self.timeOfLastPacket = time()

                self.lock.release()


    def handleMsg(self, msg):

        if msg[0] != '$':
            self.logger.debug('msg ignored: first char != $')
            return None, 0, 0

        self.logger.debug('-->>>>>>>>>>>> GDB rsp packet: %s', msg)

        # query command
        if msg[1] == '?':
            return self.createRSPPacket(self.target.getTResponse()), 1, 0
            #return self.createRSPPacket("S05"), 1, 0

        # TODO make this right
        #if msg[1] == '!':
        #    # Enable extended mode. In extended mode, the remote server is made
        #    # persistent. The 'R' packet is used to restart the program being
        #    # debugged.
        #    return self.createRSPPacket("E01"), 1, 0
        #    #if not self.persist:
        #    #    pass
        #    #else:
        #    #    pass

        # we don't send immediately the response for C and S commands
        elif msg[1] == 'C' or msg[1] == 'c':
            return self.resume()

        elif msg[1] == 'D':
            return self.detach(msg[1:]), 1, 1

        elif msg[1] == 'g':
            return self.getRegisters(), 1, 0

        elif msg[1] == 'G':
            return self.setRegisters(msg[2:]), 1, 0

        elif msg[1] == 'H':
            return self.createRSPPacket(''), 1, 0

        elif msg[1] == 'k':
            return self.kill(), 1, 1

        elif msg[1] == 'm':
            return self.getMemory(msg[2:]), 1, 0

        elif msg[1] == 'M': # write memory with hex data
            return self.writeMemoryHex(msg[2:]), 1, 0

        elif msg[1] == 'p':
            return self.readRegister(msg[2:]), 1, 0

        elif msg[1] == 'P':
            return self.writeRegister(msg[2:]), 1, 0

        elif msg[1] == 'q':
            return self.handleQuery(msg[2:]), 1, 0

        elif msg[1] == 'Q':
            return self.handleGeneralSet(msg[2:]), 1, 0

        elif msg[1] == 'S' or msg[1] == 's':
            return self.step()

        elif msg[1] == 'v':
            return self.flashOp(msg[2:]), 1, 0

        elif msg[1] == 'X': # write memory with binary data
            return self.writeMemory(msg[2:]), 1, 0

        elif msg[1] == 'Z' or msg[1] == 'z':
            return self.breakpoint(msg[1:]), 1, 0

        else:
            self.logger.error("Unknown RSP packet: %s", msg)
            return self.createRSPPacket(""), 1, 0

    def detach(self, data):
        self.logger.info("Client detached")
        resp = "OK"
        return self.createRSPPacket(resp)

    def kill(self):
        self.logger.debug("GDB kill")
        # Keep target halted and leave vector catches if in persistent mode.
        if not self.persist:
            #self.board.target.setVectorCatchFault(False) # TODO check this
            #self.board.target.setVectorCatchReset(False) # TODO 
            self.target.resume()
        return self.createRSPPacket("")

    def breakpoint(self, data):
        # handle breakpoint/watchpoint commands
        split = data.split('#')[0].split(',')
        addr = int(split[1], 16)
        self.logger.debug("GDB breakpoint %d @ %x" % (int(data[1]), addr))

        if data[1] == '0' and not self.soft_bkpt_as_hard:   
            # Empty response indicating no support for software breakpoints
            return self.createRSPPacket("")

        # handle hardware breakpoint Z1/z1
        # and software breakpoint Z0/z0
        if data[1] == '1' or (self.soft_bkpt_as_hard and data[1] == '0'):
            if data[0] == 'Z':
                if self.target.setBreakpoint(addr) == False:
                    return self.createRSPPacket('E01') #EPERM
            else:
                self.target.removeBreakpoint(addr)
            return self.createRSPPacket("OK")

        # handle hardware watchpoint Z2/z2/Z3/z3/Z4/z4
        if data[1] == '2':
            # Write-only watch
            watchpoint_type = WATCHPOINT_WRITE
        elif data[1] == '3':
            # Read-only watch
            watchpoint_type = WATCHPOINT_READ
        elif data[1] == '4':
            # Read-Write watch
            watchpoint_type = WATCHPOINT_READ_WRITE
        else:
            return self.createRSPPacket('E01') #EPERM
        size = int(split[2], 16)
        if data[0] == 'Z':
            if self.target.setWatchpoint(addr, size, watchpoint_type) == False:
                return self.createRSPPacket('E01') #EPERM
        else:
            self.target.removeWatchpoint(addr, size, watchpoint_type)
        return self.createRSPPacket("OK")

    def resume(self):
        self.ack()
        self.abstract_socket.setBlocking(0)

        self.target.resume()
        self.logger.debug("target resumed")

        val = ''

        self.timeOfLastPacket = time()
        while True:
            if self.shutdown_event.isSet():
                return self.createRSPPacket(val), 0, 0

            # Introduce a delay between non-blocking socket reads once we know
            # that the CPU isn't going to halt quickly.
            if time() - self.timeOfLastPacket > 0.5:
                sleep(0.1)
            try:
                data = self.abstract_socket.read()
                if (data[0] == '\x03'):
                    self.target.halt()
                    val = self.target.getTResponse(True)
                    self.logger.debug("receive CTRL-C")
                    break
            except:
                pass

            try:
                if self.target.getState() == TARGET_HALTED:
                    self.logger.debug("state halted")
                    val = self.target.getTResponse()
                    break
            except:
                self.logger.debug('Target is unavailable temporary.')

        self.abstract_socket.setBlocking(1)
        return self.createRSPPacket(val), 0, 0

    def step(self):
        self.ack()
        self.logger.debug("GDB step")
        self.target.step(not self.step_into_interrupt)
        return self.createRSPPacket(self.target.getTResponse()), 0, 0

    def halt(self):
        self.ack()
        self.target.halt()
        return self.createRSPPacket(self.target.getTResponse()), 0, 0

    def flashOp(self, data):
        ops = data.split(':')[0]
        self.logger.debug("flash op: %s", ops)

        if ops == 'FlashErase':
            return self.createRSPPacket("OK")

    #    elif ops == 'FlashWrite':
    #        write_addr = int(data.split(':')[1], 16)
    #        self.logger.debug("flash write addr: 0x%x", write_addr)
    #        # search for second ':' (beginning of data encoded in the message)
    #        second_colon = 0
    #        idx_begin = 0
    #        while second_colon != 2:
    #            if data[idx_begin] == ':':
    #                second_colon += 1
    #            idx_begin += 1

    #        # Get flash builder if there isn't one already
    #        if self.flashBuilder == None:
    #            self.flashBuilder = self.flash.getFlashBuilder()

    #        # Add data to flash builder
    #        self.flashBuilder.addData(write_addr, self.unescape(data[idx_begin:len(data) - 3]))


    #        return self.createRSPPacket("OK")

    #    # we need to flash everything
    #    elif 'FlashDone' in ops :

    #        def print_progress(progress):
    #            # Reset state on 0.0
    #            if progress == 0.0:
    #                print_progress.done = False

    #            # print progress bar
    #            if not print_progress.done:
    #                sys.stdout.write('\r')
    #                i = int(progress*20.0)
    #                sys.stdout.write("[%-20s] %3d%%" % ('='*i, round(progress * 100)))
    #                sys.stdout.flush()

    #            # Finish on 1.0
    #            if progress >= 1.0:
    #                if not print_progress.done:
    #                    print_progress.done = True
    #                    sys.stdout.write("\r\n")

    #        if self.hide_programming_progress:
    #            progress_cb = None
    #        else:
    #             progress_cb = print_progress

    #        self.flashBuilder.program(chip_erase = self.chip_erase, progress_cb=progress_cb, fast_verify=self.fast_program)

    #        # Set flash builder to None so that on the next flash command a new
    #        # object is used.
    #        self.flashBuilder = None

    #        return self.createRSPPacket("OK")

        elif 'Cont' in ops:
            if 'Cont?' in ops:
                # IDA-GDBServer sniff : $vCont;c;C;t;s;S;r
                return self.createRSPPacket("vCont;c;s;t")
            elif 'Cont;s' in ops:
                # TODO Add single step code here
                return self.createRSPPacket(self.target.getTResponse())

        return None

    def unescape(self, data):
        data_idx = 0

        # unpack the data into binary array
        str_unpack = str(len(data)) + 'B'
        data = unpack(str_unpack, data)
        data = list(data)

        # check for escaped characters
        while data_idx < len(data):
            if data[data_idx] == 0x7d:
                data.pop(data_idx)
                data[data_idx] = data[data_idx] ^ 0x20
            data_idx += 1

        return data


    def getMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = split[1].split('#')[0]
        length = int(length,16)

        if LOG_MEM:
            self.logger.debug("GDB getMem: addr=%x len=%x", addr, length)

        try:
            val = ''
            mem = self.target.readMemory(addr, length)
            # Flush so an exception is thrown now if invalid memory was accesses
            self.target.flush()
            val = "".join([x.encode("hex") for x in mem])
        except TransferError:
            self.logger.debug("getMemory failed at 0x%x" % addr)
            val = 'E01' #EPERM
        return self.createRSPPacket(val)

    def writeMemoryHex(self, data):
        split = data.split(',')
        addr = int(split[0], 16)

        split = split[1].split(':')
        length = int(split[0], 16)

        split = split[1].split('#')
        data = hexStringToIntList(split[0])

        if LOG_MEM:
            self.logger.debug("GDB writeMemHex: addr=%x len=%x", addr, length)

        try:
            if length > 0:
                self.target.writeMemory(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target.flush()
            resp = "OK"
        except TransferError:
            self.logger.debug("writeMemory failed at 0x%x" % addr)
            resp = 'E01' #EPERM

        return self.createRSPPacket(resp)

    def writeMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = int(split[1].split(':')[0], 16)

        if LOG_MEM:
            self.logger.debug("GDB writeMem: addr=%x len=%x", addr, length)

        idx_begin = 0
        for i in range(len(data)):
            if data[i] == ':':
                idx_begin += 1
                break
            idx_begin += 1

        data = data[idx_begin:len(data) - 3]
        data = self.unescape(data)

        try:
            if length > 0:
                self.target.writeMemory(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target.flush()
            resp = "OK"
        except TransferError:
            self.logger.debug("writeMemory failed at 0x%x" % addr)
            resp = 'E01' #EPERM

        return self.createRSPPacket(resp)

    def readRegister(self, which):
        return self.createRSPPacket(self.target.gdbGetRegister(which))

    def writeRegister(self, data):
        reg = int(data.split('=')[0], 16)
        val = data.split('=')[1].split('#')[0]
        self.target.setRegister(reg, val)
        return self.createRSPPacket("OK")

    def getRegisters(self):
        """Return the complete list of registers."""
        return self.createRSPPacket(self.target.getRegisterContext())

    def setRegisters(self, data):
        """Return the value of a specific register."""
        self.target.setRegisterContext(data)
        return self.createRSPPacket("OK")

    def handleQuery(self, msg):
        """Handle query message from RSP client."""

        query = msg.split(':')
        self.logger.debug('GDB received query: %s', query)

        if query is None:
            self.logger.error('GDB received query packet malformed')
            return None

        if query[0] == 'Supported':
            # Save features sent by gdb.
            self.gdb_features = query[1].split(';')

            # Build our list of features.
            features = []
            #features.append('qXfer:features:read+')
            #features.append('QStartNoAckMode+') # TODO check this
            features.append('PacketSize=' + hex(self.packet_size)[2:])
            #if hasattr(self.target, 'memoryMapXML'):
            #    features.append('qXfer:memory-map:read+')
            resp = ';'.join(features)
            return self.createRSPPacket(resp)

        elif query[0] == 'fThreadInfo':
            return self.createRSPPacket("m26a")

        elif query[0] == 'sThreadInfo':
            return self.createRSPPacket("l")

        #elif query[0] == 'Xfer':

        #    if query[1] == 'features' and query[2] == 'read' and \
        #       query[3] == 'target.xml':
        #        data = query[4].split(',')
        #        resp = self.handleQueryXML('read_feature', int(data[0], 16), int(data[1].split('#')[0], 16))
        #        return self.createRSPPacket(resp)

        #    elif query[1] == 'memory-map' and query[2] == 'read':
        #        data = query[4].split(',')
        #        resp = self.handleQueryXML('memory_map', int(data[0], 16), int(data[1].split('#')[0], 16))
        #        return self.createRSPPacket(resp)

        #    else:
        #        return None

        elif query[0] == 'C#b4':
            return self.createRSPPacket("")

        elif query[0].find('Attached') != -1:
            return self.createRSPPacket("1")

        elif query[0].find('TStatus') != -1:
            return self.createRSPPacket("")

        elif query[0].find('Tf') != -1:
            return self.createRSPPacket("")

        elif 'Offsets' in query[0]:
            resp = "Text=0;Data=0;Bss=0"
            return self.createRSPPacket(resp)

        elif 'Symbol' in query[0]:
            resp = "OK"
            return self.createRSPPacket(resp)

        elif query[0].startswith('Rcmd,'):
            cmd = hexDecode(query[0][5:].split('#')[0])
            self.logger.debug('Remote command: %s', cmd)

            safecmd = {
                'reset' : ['Reset target', 0x1],
                'halt'  : ['Halt target', 0x2],
                'resume': ['Resume target', 0x4],
                'help'  : ['Display this help', 0x80],
            }
            resultMask = 0x00
            if cmd == 'help':
                resp = ''
                for k,v in safecmd.items():
                    resp += '%s\t%s\n' % (k,v[0])
                resp = hexEncode(resp)
            else:
                cmdList = cmd.split(' ')
                #check whether all the cmds is valid cmd for monitor
                for cmd_sub in cmdList:
                    if not cmd_sub in safecmd:
                        #error cmd for monitor
                        self.logger.warning("Invalid mon command '%s'", cmd)
                        resp = 'Invalid Command: "%s"\n' % cmd
                        resp = hexEncode(resp)
                        return self.createRSPPacket(resp)
                    else:
                        resultMask = resultMask | safecmd[cmd_sub][1]
                #if it's a single cmd, just launch it!
                if len(cmdList) == 1:
                    tmp = eval ('self.target.%s()' % cmd_sub)
                    self.logger.debug(tmp)
                    resp = "OK"
                else:
                    #10000001 for help reset, so output reset cmd help information
                    if resultMask == 0x81:
                        resp = 'Reset the target\n'
                        resp = hexEncode(resp)
                    #10000010 for help halt, so output halt cmd help information
                    elif resultMask == 0x82:
                        resp = 'Halt the target\n'
                        resp = hexEncode(resp)
                    #10000100 for help resume, so output resume cmd help information
                    elif resultMask == 0x84:
                        resp = 'Resume the target\n'
                        resp = hexEncode(resp)
                    #11 for reset halt cmd, so launch self.target.resetStopOnReset()
                    elif resultMask == 0x3:
                        resp = "OK"
                        self.target.resetStopOnReset()
                    #111 for reset halt resume cmd, so launch self.target.resetStopOnReset() and self.target.resume()
                    elif resultMask == 0x7:
                        resp = "OK"
                        self.target.resetStopOnReset()
                        self.target.resume()
                    else:
                        self.logger.warning("Invalid mon command '%s'", cmd)
                        resp = 'Invalid Command: "%s"\n' % cmd
                        resp = hexEncode(resp)

                if self.target.getState() != TARGET_HALTED:
                    self.logger.error("Remote command left target running!")
                    self.logger.error("Forcing target to halt")
                    self.target.halt()

            return self.createRSPPacket(resp)

        else:
            pass

        return self.createRSPPacket("")

    def handleGeneralSet(self, msg):
        self.logger.debug("GDB general set: %s", msg)
        feature = msg.split('#')[0]

        if feature == 'StartNoAckMode':
            # Disable acks after the reply and ack.
            self.clear_send_acks = True
            return self.createRSPPacket("OK")
        else:
            return self.createRSPPacket("")

    def handleQueryXML(self, query, offset, size):
        self.logger.debug('GDB query %s: offset: %s, size: %s', query, offset, size)
        xml = ''
        if query == 'memory_map':
            xml = self.target.memoryMapXML
        elif query == 'read_feature':
            xml = self.target.getTargetXML()

        size_xml = len(xml)

        prefix = 'm'

        if offset > size_xml:
            self.logger.error('GDB: offset target.xml > size!')
            return

        if size > (self.packet_size - 4):
            size = self.packet_size - 4

        nbBytesAvailable = size_xml - offset

        if size > nbBytesAvailable:
            prefix = 'l'
            size = nbBytesAvailable

        resp = prefix + xml[offset:offset + size]

        return resp


    def createRSPPacket(self, data):
        resp = '$' + data + '#'

        c = 0
        checksum = 0
        for c in data:
            checksum += ord(c)
        checksum = checksum % 256
        checksum = hex(checksum)

        if int(checksum[2:], 16) < 0x10:
            resp += '0'
        resp += checksum[2:]

        #self.logger.debug('--<<<<<<<<<<<< GDB rsp packet: %s', resp)
        return resp

    def ack(self):
        if self.send_acks:
            self.abstract_socket.write("+")


