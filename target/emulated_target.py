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


# Map from register name to DCRSR register index.
#
# The CONTROL, FAULTMASK, BASEPRI, and PRIMASK registers are special in that they share the
# same DCRSR register index and are returned as a single value. In this dict, these registers
# have negative values to signal to the register read/write functions that special handling
# is necessary. The values are the byte number containing the register value, plus 1 and then
# negated. So -1 means a mask of 0xff, -2 is 0xff00, and so on. The actual DCRSR register index
# for these combined registers has the key of 'cfbp'.
CORE_REGISTER = {
                 'r0': 0,
                 'r1': 1,
                 'r2': 2,
                 'r3': 3,
                 'r4': 4,
                 'r5': 5,
                 'r6': 6,
                 'r7': 7,
                 'r8': 8,
                 'r9': 9,
                 'r10': 10,
                 'r11': 11,
                 'r12': 12,
                 'sp': 13,
                 'lr': 14,
                 'pc': 15,
                 'xpsr': 16,
                 'msp': 17,
                 'psp': 18,
                 'cfbp': 20,
                 'control': -4,
                 'faultmask': -3,
                 'basepri': -2,
                 'primask': -1,
                 'fpscr': 33,
                 's0': 0x40,
                 's1': 0x41,
                 's2': 0x42,
                 's3': 0x43,
                 's4': 0x44,
                 's5': 0x45,
                 's6': 0x46,
                 's7': 0x47,
                 's8': 0x48,
                 's9': 0x49,
                 's10': 0x4a,
                 's11': 0x4b,
                 's12': 0x4c,
                 's13': 0x4d,
                 's14': 0x4e,
                 's15': 0x4f,
                 's16': 0x50,
                 's17': 0x51,
                 's18': 0x52,
                 's19': 0x53,
                 's20': 0x54,
                 's21': 0x55,
                 's22': 0x56,
                 's23': 0x57,
                 's24': 0x58,
                 's25': 0x59,
                 's26': 0x5a,
                 's27': 0x5b,
                 's28': 0x5c,
                 's29': 0x5d,
                 's30': 0x5e,
                 's31': 0x5f,
                 }


class EmulatedTarget(Target):


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
        RegisterInfo('r0',      32,         'int',          'general'),
        RegisterInfo('r1',      32,         'int',          'general'),
        RegisterInfo('r2',      32,         'int',          'general'),
        RegisterInfo('r3',      32,         'int',          'general'),
        RegisterInfo('r4',      32,         'int',          'general'),
        RegisterInfo('r5',      32,         'int',          'general'),
        RegisterInfo('r6',      32,         'int',          'general'),
        RegisterInfo('r7',      32,         'int',          'general'),
        RegisterInfo('r8',      32,         'int',          'general'),
        RegisterInfo('r9',      32,         'int',          'general'),
        RegisterInfo('r10',     32,         'int',          'general'),
        RegisterInfo('r11',     32,         'int',          'general'),
        RegisterInfo('r12',     32,         'int',          'general'),
        RegisterInfo('sp',      32,         'data_ptr',     'general'),
        RegisterInfo('lr',      32,         'int',          'general'),
        RegisterInfo('pc',      32,         'code_ptr',     'general'),
        RegisterInfo('xpsr',    32,         'int',          'general'),
        RegisterInfo('msp',     32,         'int',          'general'),
        RegisterInfo('psp',     32,         'int',          'general'),
        RegisterInfo('primask', 32,         'int',          'general'),
        RegisterInfo('control', 32,         'int',          'general'),
        ]

    def __init__(self, emu):
        super(EmulatedTarget, self).__init__(None)
        self.emu = emu

    #def setFlash(self, flash):
    #    pass

    def init(self, initial_setup=True, bus_accessible=True):
        """Emulated target initial setup."""
        self.emu.start()

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
#                logging.warning("Unknown AHB IDR: 0x%x" % ahb_idr)

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
        """Return hexadecimal dump of registers as expected by GDB."""

        logging.debug("GDB getting register context")
        resp = ''
        reg_num_list = map(lambda reg:reg.reg_num, self.register_list)

        vals = self.readCoreRegistersRaw(reg_num_list)
        #print("Vals: %s" % vals)
        for reg, regValue in zip(self.register_list, vals):
            resp += conversion.intToHex8(regValue)
            logging.debug("GDB reg: %s = 0x%X", reg.name, regValue)

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

        ## Read all results
        #reg_vals = []
        #for reg in reg_list:
        #    dhcsr_val = self.readMemory(DHCSR, mode=READ_END)
        #    assert dhcsr_val & S_REGRDY
        #    # read DCRDR
        #    val = self.readMemory(DCRDR, mode=READ_END)

        #    # Special handling for registers that are combined into a single DCRSR number.
        #    if (reg < 0) and (reg >= -4):
        #        val = (val >> ((-reg - 1) * 8)) & 0xff

        #    reg_vals.append(val)

        return reg_vals



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
