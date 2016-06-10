"""
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
from xml.etree.ElementTree import Element, SubElement, tostring
import logging
import struct

from .target import Target
from .target import TARGET_RUNNING, TARGET_HALTED, WATCHPOINT_READ, WATCHPOINT_WRITE, WATCHPOINT_READ_WRITE
from gdbserver import signals
from utility import conversion

# Maps the fault code found in the IPSR to a GDB signal value.
FAULT = [
            signals.SIGSTOP,
            signals.SIGSTOP,    # Reset
            signals.SIGINT,     # NMI
            signals.SIGSEGV,    # HardFault
            signals.SIGSEGV,    # MemManage
            signals.SIGBUS,     # BusFault
            signals.SIGILL,     # UsageFault
                                                # The rest are not faults
         ]


class EmulatedTarget(Target):

    def __init__(self, emu):
        super(EmulatedTarget, self).__init__(None)
        self.emu = emu

    #def setFlash(self, flash):
    #    pass

    def init(self):
        self.emu.start()

    def info(self, request):
        return

    def flush(self):
        # XXX Is there something else to do here?
        ##self.transport.flush()
        pass

    def readIDCode(self):
        return

    def halt(self):
        return

    def step(self):
        return

    def resume(self):
        return

    def writeMemory(self, addr, value, transfer_size = 32):
        """
        write a memory location.
        By default the transfer size is a word
        """
        self.emu.write_memory(addr, value)

    def readMemory(self, addr, transfer_size = 32):#, mode = READ_NOW):
        """
        read a memory location. By default, a word will
        be read
        """
        return self.emu.read_memory(addr, transfer_size)

    def readCoreRegister(self, id):
        return

    def writeCoreRegister(self, id):
        return

    def setBreakpoint(self, addr):
        return

    def removeBreakpoint(self, addr):
        return

    def setWatchpoint(addr, size, type):
        return

    def removeWatchpoint(addr, size, type):
        return

    def reset(self):
        return

    def getState(self):
        return

    # GDB functions
    def getTargetXML(self):
        return ''

    def getMemoryMapXML(self):
        return self.memoryMapXML

    def getRegisterContext(self):
        return ''

    def setRegisterContext(self, data):
        return

    def setRegister(self, reg, data):
        return

    def gdbGetRegister(self, reg):
        resp = ''
        #if reg < len(self.register_list):
        #    regName = self.register_list[reg].name
        #    regValue = self.readCoreRegisterRaw(regName)
        #    resp = conversion.intToHex8(regValue)
        #    logging.debug("GDB reg: %s = 0x%X", regName, regValue)
        return resp

    def getTResponse(self, gdbInterrupt = False):
        """
        Returns a GDB T response string.  This includes:
            The signal encountered.
            The current value of the important registers (sp, lr, pc).
        """
        return "T05"
        #if gdbInterrupt:
        #    response = 'T' + conversion.intToHex2(signals.SIGINT)
        #else:
        #    response = 'T' + conversion.intToHex2(self.getSignalValue())

        ## Append fp(r7), sp(r13), lr(r14), pc(r15)
        #response += self.getRegIndexValuePairs([7, 13, 14, 15])

        #return response

    #def getSignalValue(self):
    #    if self.isDebugTrap():
    #        return signals.SIGTRAP

    #    fault = self.readCoreRegister('xpsr') & 0xff
    #    try:
    #        signal = FAULT[fault]
    #    except:
    #        # If not a fault then default to SIGSTOP
    #        signal = signals.SIGSTOP
    #    logging.debug("GDB lastSignal: %d", signal)
    #    return signal
