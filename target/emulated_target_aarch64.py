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
import struct
import logging

import colorlog

from .target import Target
from .target import TARGET_RUNNING, TARGET_HALTED, WATCHPOINT_READ, WATCHPOINT_WRITE, WATCHPOINT_READ_WRITE
from gdbserver import signals
from utility import conversion
from gdbserver.utility import *


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


# Map from register name to DCRSR register index.
#
# The CONTROL, FAULTMASK, BASEPRI, and PRIMASK registers are special in that they share the
# same DCRSR register index and are returned as a single value. In this dict, these registers
# have negative values to signal to the register read/write functions that special handling
# is necessary. The values are the byte number containing the register value, plus 1 and then
# negated. So -1 means a mask of 0xff, -2 is 0xff00, and so on. The actual DCRSR register index
# for these combined registers has the key of 'cfbp'.
CORE_REGISTER = {
                #"x0"    : 0,
                #"x1"    : 1,
                #"x2"    : 2,
                #"x3"    : 3,
                #"x4"    : 4,
                #"x5"    : 5,
                #"x6"    : 6,
                #"x7"    : 7,
                #"x8"    : 8,
                #"x9"    : 9,
                #"x10"   : 10,
                #"x11"   : 11,
                #"x12"   : 12,
                #"x13"   : 13,
                #"x14"   : 14,
                #"x15"   : 15,
                #"x16"   : 16,
                #"x17"   : 17,
                #"x18"   : 18,
                #"x19"   : 19,
                #"x20"   : 20,
                #"x21"   : 21,
                #"x22"   : 22,
                #"x23"   : 23,
                #"x24"   : 24,
                #"x25"   : 25,
                #"x26"   : 26,
                #"x27"   : 27,
                #"x28"   : 28,
                #"x29"   : 29,
                #"x30"   : 30,
                #"sp"    : 31,
                #"xzr"   : 32,
                #"pc"    : 33,

                "r0"    : 0,
                "r1"    : 1,
                "r2"    : 2,
                "r3"    : 3,
                "r4"    : 4,
                "r5"    : 5,
                "r6"    : 6,
                "r7"    : 7,
                "r8"    : 8,
                "r9"    : 9,
                "r10"   : 10,
                "r11"   : 11,
                "r12"   : 12,
                "r13"   : 13,
                "r14"   : 14,
                "r15"   : 15,
                "r16"   : 16,
                "r17"   : 17,
                "r18"   : 18,
                "r19"   : 19,
                "r20"   : 20,
                "r21"   : 21,
                "r22"   : 22,
                "r23"   : 23,
                "r24"   : 24,
                "r25"   : 25,
                "r26"   : 26,
                "r27"   : 27,
                "r28"   : 28,
                "r29"   : 29,
                "r30"   : 30,
                "r31"   : 31,
                "pc"    : 32,
                }



class EmulatedTargetAArch64(Target):


    class RegisterInfo(object):
        def __init__(self, name, bitsize, reg_type, reg_group):
            self.name = name
            self.reg_num = CORE_REGISTER[name]
            self.gdb_xml_attrib = {}
            self.gdb_xml_attrib['name'] = str(name)
            self.gdb_xml_attrib['bitsize'] = str(bitsize)
            self.gdb_xml_attrib['type'] = str(reg_type)
            self.gdb_xml_attrib['group'] = str(reg_group)

    regs_general = [
        #            Name       bitsize     type            group
#        RegisterInfo("x0"  ,   32,         'int',          'general'),
#        RegisterInfo("x1"  ,   32,         'int',          'general'),
#        RegisterInfo("x2"  ,   32,         'int',          'general'),
#        RegisterInfo("x3"  ,   32,         'int',          'general'),
#        RegisterInfo("x4"  ,   32,         'int',          'general'),
#        RegisterInfo("x5"  ,   32,         'int',          'general'),
#        RegisterInfo("x6"  ,   32,         'int',          'general'),
#        RegisterInfo("x7"  ,   32,         'int',          'general'),
#        RegisterInfo("x8"  ,   32,         'int',          'general'),
#        RegisterInfo("x9"  ,   32,         'int',          'general'),
#        RegisterInfo("x10" ,   32,         'int',          'general'),
#        RegisterInfo("x11" ,   32,         'int',          'general'),
#        RegisterInfo("x12" ,   32,         'int',          'general'),
#        RegisterInfo("x13" ,   32,         'data_ptr',     'general'),
#        RegisterInfo("x14" ,   32,         'int',          'general'),
#        RegisterInfo("x15" ,   32,         'code_ptr',     'general'),
#        RegisterInfo("x16" ,   32,         'int',          'general'),
#        RegisterInfo("x17" ,   32,         'int',          'general'),
#        RegisterInfo("x18" ,   32,         'int',          'general'),
#        RegisterInfo("x19" ,   32,         'int',          'general'),
#        RegisterInfo("x20" ,   32,         'int',          'general'),
#        RegisterInfo("x21" ,   32,         'int',          'general'),
#        RegisterInfo("x22" ,   32,         'int',          'general'),
#        RegisterInfo("x23" ,   32,         'int',          'general'),
#        RegisterInfo("x24" ,   32,         'int',          'general'),
#        RegisterInfo("x25" ,   32,         'int',          'general'),
#        RegisterInfo("x26" ,   32,         'int',          'general'),
#        RegisterInfo("x27" ,   32,         'int',          'general'),
#        RegisterInfo("x28" ,   32,         'int',          'general'),
#        RegisterInfo("x29" ,   32,         'int',          'general'),
#        RegisterInfo("x30" ,   32,         'data_ptr',     'general'),
#        RegisterInfo("sp"  ,   32,         'int',          'general'),
#        RegisterInfo("xzr" ,   32,         'code_ptr',     'general'),
#        RegisterInfo("pc"  ,   32,         'int',          'general'),

        RegisterInfo("r0"  ,   32,         'int',          'general'),
        RegisterInfo("r1"  ,   32,         'int',          'general'),
        RegisterInfo("r2"  ,   32,         'int',          'general'),
        RegisterInfo("r3"  ,   32,         'int',          'general'),
        RegisterInfo("r4"  ,   32,         'int',          'general'),
        RegisterInfo("r5"  ,   32,         'int',          'general'),
        RegisterInfo("r6"  ,   32,         'int',          'general'),
        RegisterInfo("r7"  ,   32,         'int',          'general'),
        RegisterInfo("r8"  ,   32,         'int',          'general'),
        RegisterInfo("r9"  ,   32,         'int',          'general'),
        RegisterInfo("r10" ,   32,         'int',          'general'),
        RegisterInfo("r11" ,   32,         'int',          'general'),
        RegisterInfo("r12" ,   32,         'int',          'general'),
        RegisterInfo("r13" ,   32,         'data_ptr',     'general'),
        RegisterInfo("r14" ,   32,         'int',          'general'),
        RegisterInfo("r15" ,   32,         'code_ptr',     'general'),
        RegisterInfo("r16" ,   32,         'int',          'general'),
        RegisterInfo("r17" ,   32,         'int',          'general'),
        RegisterInfo("r18" ,   32,         'int',          'general'),
        RegisterInfo("r19" ,   32,         'int',          'general'),
        RegisterInfo("r20" ,   32,         'int',          'general'),
        RegisterInfo("r21" ,   32,         'int',          'general'),
        RegisterInfo("r22" ,   32,         'int',          'general'),
        RegisterInfo("r23" ,   32,         'int',          'general'),
        RegisterInfo("r24" ,   32,         'int',          'general'),
        RegisterInfo("r25" ,   32,         'int',          'general'),
        RegisterInfo("r26" ,   32,         'int',          'general'),
        RegisterInfo("r27" ,   32,         'int',          'general'),
        RegisterInfo("r28" ,   32,         'int',          'general'),
        RegisterInfo("r29" ,   32,         'int',          'general'),
        RegisterInfo("r30" ,   32,         'data_ptr',     'general'),
        RegisterInfo("r31" ,   32,         'int',          'general'),
        RegisterInfo("pc"  ,   32,         'int',          'general'),
        ]

    def __init__(self, emu, log_level=logging.DEBUG):
        super(EmulatedTargetAArch64, self).__init__(emu=emu)

        # setup logging
        log_format = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"

        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        handler.setFormatter(colorlog.ColoredFormatter(log_format))

        self.logger = colorlog.getLogger(type(self).__name__)
        self.logger.setLevel(log_level)
        self.logger.addHandler(handler)

    def init(self, initial_setup=True, bus_accessible=True):
        """Emulated target initial setup."""
        self.emu.init()

#        if initial_setup:
#            self.idcode = self.readIDCode()
#            # select bank 0 (to access DRW and TAR)
#            self.transport.writeDP(DP_REG['SELECT'], 0)
#            self.transport.writeDP(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ)
#
#            while True:
#                r = self.transport.readDP(DP_REG['CTRL_STAT'])
#                if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
#                    break
#
#            self.transport.writeDP(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE)
#            self.transport.writeDP(DP_REG['SELECT'], 0)
#
#            ahb_idr = self.transport.readAP(AP_REG['IDR'])
#            if ahb_idr in AHB_IDR_TO_WRAP_SIZE:
#                self.auto_increment_page_size = AHB_IDR_TO_WRAP_SIZE[ahb_idr]
#            else:
#                # If unknown use the smallest size supported by all targets.
#                # A size smaller than the supported size will decrease performance
#                # due to the extra address writes, but will not create any
#                # read/write errors.
#                auto_increment_page_size = 0x400
#                self.logger.warning("Unknown AHB IDR: 0x%x" % ahb_idr)

        if bus_accessible:
#            self.halt()
#            self.setupFPB()
#            self.readCoreType()
#            self.checkForFPU()
#            self.setupDWT()
#
            # Build register_list and targetXML
            self.register_list = []
            xml_root = Element('target')
#            xml_regs_general = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.m-profile")
            for reg in self.regs_general:
                self.register_list.append(reg)
#                SubElement(xml_regs_general, 'reg', **reg.gdb_xml_attrib)
#            # Check if target has ARMv7 registers
#            if self.core_type in  (ARM_CortexM3, ARM_CortexM4):
#                for reg in self.regs_system_armv7_only:
#                    self.register_list.append(reg)
#                    SubElement(xml_regs_general, 'reg',  **reg.gdb_xml_attrib)
#            # Check if target has FPU registers
#            if self.has_fpu:
#                #xml_regs_fpu = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.vfp")
#                for reg in self.regs_float:
#                    self.register_list.append(reg)
#                    SubElement(xml_regs_general, 'reg', **reg.gdb_xml_attrib)
#            self.targetXML = '<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">' + tostring(xml_root)


    def info(self, request):
        return

    def flush(self):
        # XXX Is there something else to do here?
        ##self.transport.flush()
        pass

    def readIDCode(self):
        return

    def halt(self):
        self.state = TARGET_HALTED
        self.emu.stop()
        return

    def step(self):
        return

    def resume(self, count=0):
        self.state = TARGET_RUNNING

        self.emu.start(count)
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

    def setBreakpoint(self, address):
        """Set a breakpoint at the specified address."""
        self.emu.set_breakpoint(address)
        return

    def removeBreakpoint(self, address):
        """Remove the breakpoint at the specified address."""
        self.emu.remove_breakpoint(address)
        return

    def setWatchpoint(addr, size, type):
        return

    def removeWatchpoint(addr, size, type):
        return

    def reset(self):
        return

    # GDB functions
    def getTargetXML(self):
        return ''

    def getMemoryMapXML(self):
        return self.memoryMapXML

    def breakpoint_callback(self, address):
        """Callback function when breakpoints are hit."""
        self.logger.warning("I've hit a breakpoint at 0x%08X" % address)
        self.state = TARGET_HALTED

    def getRegisterContext(self):
        """Return hexadecimal dump of registers as expected by GDB."""

        self.logger.debug("GDB getting register context")
        resp = ''
        reg_num_list = map(lambda reg:reg.reg_num, self.register_list)

        for idx, reg in enumerate(self.register_list):
            regValue = self.emu.read_register(reg.name)

            #resp += struct.pack(self.endian + self.pack_format, regValue).encode("hex") 
            resp += struct.pack(self.endian + self.pack_format, idx).encode("hex") 

            self.logger.debug("GDB reg: %%s = 0x%%0%dX" % (self.step*2), reg.name, regValue)

        print resp
        return resp

    def registerNameToIndex(self, reg):
        """
        return register index based on name.
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        if isinstance(reg, str):

            reg = CORE_REGISTER.get(reg.lower(), None)

            if not reg:
                self.logger.error('cannot find %s core register', reg)
                return None

        return reg

    def readCoreRegistersRaw(self, reg_list):
        """
        Read one or more core registers

        Read core registers in reg_list and return a list of values.
        If any register in reg_list is a string, find the number
        associated to this register in the lookup table CORE_REGISTER.
        """
        # convert to index only
        reg_list = [self.registerNameToIndex(reg) for reg in reg_list]

        ## Sanity check register values
        #for reg in reg_list:
        #    if reg not in CORE_REGISTER.values():
        #        raise ValueError("unknown reg: %d" % reg)
        #    elif ((reg >= 128) or (reg == 33)) and (not self.has_fpu):
        #        raise ValueError("attempt to read FPU register without FPU")

        ## Begin all reads and writes
        #for reg in reg_list:
        #    if (reg < 0) and (reg >= -4):
        #        reg = CORE_REGISTER['cfbp']

        #    # write id in DCRSR
        #    self.writeMemory(DCRSR, reg)

        #    # Technically, we need to poll S_REGRDY in DHCSR here before reading DCRDR. But
        #    # we're running so slow compared to the target that it's not necessary.
        #    # Read it and assert that S_REGRDY is set

        #    self.readMemory(DHCSR, mode=READ_START)
        #    self.readMemory(DCRDR, mode=READ_START)

        # Read all results
        reg_vals = []
        for index,reg in enumerate(reg_list):
            reg_vals.append(index)
        #    dhcsr_val = self.readMemory(DHCSR, mode=READ_END)
        #    assert dhcsr_val & S_REGRDY
        #    # read DCRDR
        #    val = self.readMemory(DCRDR, mode=READ_END)

        #    # Special handling for registers that are combined into a single DCRSR number.
        #    if (reg < 0) and (reg >= -4):
        #        val = (val >> ((-reg - 1) * 8)) & 0xff

        #    reg_vals.append(val)
            pass

        return reg_vals

    def setRegisterContext(self, data):
        """Store the specified values for the appropriate registers."""
        data = hexDecode(data)
        #regs_values = struct.unpack("<" + "I" * (len(data)/4), data)
        regs_values = struct.unpack(self.endian + self.pack_format * (len(data)/self.step), data)
        for i, value in enumerate(regs_values):
            self.emu.write_register(self.regs_general[i].name, value)
        return


    def setRegister(self, reg, data):
        return

    def gdbGetRegister(self, reg):
        resp = ''
        if reg < len(self.register_list):
            regName = self.register_list[reg].name
            regValue = self.emu.read_register(regName)  #self.readCoreRegisterRaw(regName)
            resp = conversion.intToHex8(regValue)
            self.logger.debug("GDB reg: %s = 0x%X", regName, regValue)
        return resp

    def getTResponse(self, gdbInterrupt = False):
        """
        Returns a GDB T response string.  This includes:
            The signal encountered.
            The current value of the important registers (sp, lr, pc).
        """
        #return "T05" # TODO FIXME
        resp = []
        resp.append("T0506:0 *,")

        regValue = self.emu.read_register("rsp")
        enc_reg = struct.pack(self.endian + self.pack_format, regValue).encode("hex")
        resp.append("07:" + enc_reg)

        regValue = self.emu.read_register("rip")
        enc_reg = struct.pack(self.endian + self.pack_format, regValue).encode("hex")
        resp.append("10:" + enc_reg)

        resp.append("thread:26a ")
        resp.append("core:1")

        self.logger.debug("T Response : %s" % resp)
        return ";".join(resp)
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
    #    self.logger.debug("GDB lastSignal: %d", signal)
    #    return signal
