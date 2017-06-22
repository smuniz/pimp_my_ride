"""

"""
from xml.etree.ElementTree import Element, SubElement, tostring
import struct
import logging

import colorlog

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
                'zero' : 0,
                'at' : 1,
                'v0' : 2,
                'v1' : 3,
                'a0' : 4,
                'a1' : 5,
                'a2' : 6,
                'a3' : 7,
                't0' : 8,
                't1' : 9,
                't2' : 10,
                't3' : 11,
                't4' : 12,
                't5' : 13,
                't6' : 14,
                't7' : 15,
                's0' : 16,
                's1' : 17,
                's2' : 18,
                's3' : 19,
                's4' : 20,
                's5' : 21,
                's6' : 22,
                's7' : 23,
                't8' : 24,
                't9' : 25,
                'k0' : 26,
                'k1' : 27,
                'gp' : 28,
                'sp' : 29,
                'fp' : 30,
                'ra' : 31,
                'status' : 32,
                'lo' : 33,
                'hi' : 34,
                'badvaddr' : 35,
                'cause' : 36,
                'pc' : 37,

                 #'r7': 7,
                 #'r8': 8,
                 #'r9': 9,
                 #'r10': 10,
                 #'r11': 11,
                 #'r12': 12,
                 #'sp': 13,
                 #'lr': 14,
                 #'pc': 15,
                 #'xpsr': 16,
                 #'msp': 17,
                 #'psp': 18,
                 #'cfbp': 20,
                 #'control': -4,
                 #'faultmask': -3,
                 #'basepri': -2,
                 #'primask': -1,
                 #'fpscr': 33,
                 #'s0': 0x40,
                 #'s1': 0x41,
                 #'s2': 0x42,
                 #'s3': 0x43,
                 #'s4': 0x44,
                 #'s5': 0x45,
                 #'s6': 0x46,
                 #'s7': 0x47,
                 #'s8': 0x48,
                 #'s9': 0x49,
                 #'s10': 0x4a,
                 #'s11': 0x4b,
                 #'s12': 0x4c,
                 #'s13': 0x4d,
                 #'s14': 0x4e,
                 #'s15': 0x4f,
                 #'s16': 0x50,
                 #'s17': 0x51,
                 #'s18': 0x52,
                 #'s19': 0x53,
                 #'s20': 0x54,
                 #'s21': 0x55,
                 #'s22': 0x56,
                 #'s23': 0x57,
                 #'s24': 0x58,
                 #'s25': 0x59,
                 #'s26': 0x5a,
                 #'s27': 0x5b,
                 #'s28': 0x5c,
                 #'s29': 0x5d,
                 #'s30': 0x5e,
                 #'s31': 0x5f,
                 }


class EmulatedTargetMips(Target):


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
        RegisterInfo('zero',    32,         'int',          'general'),
        RegisterInfo('at',      32,         'int',          'general'),
        RegisterInfo('v0',      32,         'int',          'general'),
        RegisterInfo('v1',      32,         'int',          'general'),
        RegisterInfo('a0',      32,         'int',          'general'),
        RegisterInfo('a1',      32,         'int',          'general'),
        RegisterInfo('a2',      32,         'int',          'general'),
        RegisterInfo('a3',      32,         'int',          'general'),
        RegisterInfo('t0',      32,         'int',          'general'),
        RegisterInfo('t1',      32,         'int',          'general'),
        RegisterInfo('t2',      32,         'int',          'general'),
        RegisterInfo('t3',      32,         'int',          'general'),
        RegisterInfo('t4',      32,         'int',          'general'),
        RegisterInfo('t5',      32,         'int',          'general'),
        RegisterInfo('t6',      32,         'int',          'general'),
        RegisterInfo('t7',      32,         'int',          'general'),
        RegisterInfo('s0',      32,         'int',          'general'),
        RegisterInfo('s1',      32,         'int',          'general'),
        RegisterInfo('s2',      32,         'int',          'general'),
        RegisterInfo('s3',      32,         'int',          'general'),
        RegisterInfo('s4',      32,         'int',          'general'),
        RegisterInfo('s5',      32,         'int',          'general'),
        RegisterInfo('s6',      32,         'int',          'general'),
        RegisterInfo('s7',      32,         'int',          'general'),
        RegisterInfo('t8',      32,         'int',          'general'),
        RegisterInfo('t9',      32,         'int',          'general'),
        RegisterInfo('k0',      32,         'int',          'general'),
        RegisterInfo('k1',      32,         'int',          'general'),
        RegisterInfo('gp',      32,         'int',          'general'),
        RegisterInfo('sp',      32,         'int',          'general'),
        RegisterInfo('fp',      32,         'int',          'general'),
        RegisterInfo('ra',      32,         'int',          'general'),
        RegisterInfo('status',  32,         'int',          'general'),
        RegisterInfo('lo',      32,         'int',          'general'),
        RegisterInfo('hi',      32,         'int',          'general'),
        RegisterInfo('badvaddr',32,         'int',          'general'),
        RegisterInfo('cause',   32,         'int',          'general'),
        RegisterInfo('pc',      32,         'int',          'general'),
        ]

    def __init__(self, emu, log_level=logging.DEBUG):
        super(EmulatedTargetMips, self).__init__(None)

        # setup logging
        log_format = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"

        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        handler.setFormatter(colorlog.ColoredFormatter(log_format))

        self.logger = colorlog.getLogger(type(self).__name__)
        self.logger.setLevel(log_level)
        self.logger.addHandler(handler)

        self.emu = emu

        self.state = None

    #def setFlash(self, flash):
    #    pass

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
        """..."""
        self.state = TARGET_HALTED
        self.emu.stop()
        return

    def step(self):
        #self.state = TARGET_RUNNING)
        return

    def resume(self, count=0):
        """..."""
        #try:
        self.state = TARGET_RUNNING

        self.emu.start(count)
        #self.emu.start(0)
        #except PimpMyRideException, err:
        return

    def writeMemory(self, addr, value, transfer_size=32):
        """
        Write a specific memory location.
        By default the transfer size is a word
        """
        self.emu.write_memory(addr, value)

    def readMemory(self, addr, transfer_size=32):#, mode = READ_NOW):
        """Read a memory location. By default, a word will be read."""
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

    @property
    def state(self):
        """Return the current state of the application."""
        return self._state

    @state.setter
    def state(self, state):
        """Store the current state of the application."""
        self._state = state

    # GDB functions
    def getTargetXML(self):
        return ''

    def getMemoryMapXML(self):
        return self.memoryMapXML

    def breakpoint_callback(self, address):
        """Callback function when breakpoints are hit."""
        self.logger.error("I've hit a breakpoint at 0x%08X" % address)
        self.state = TARGET_HALTED
        #self.createRSPPacket("S05")
        #self.createRSPPacket(self.getTResponse())
        #raise Exception("matanga")

    def getRegisterContext(self):
        """Return hexadecimal dump of registers as expected by GDB."""

        self.logger.debug("GDB getting register context")
        resp = ''
        reg_num_list = map(lambda reg:reg.reg_num, self.register_list)
        print "\n*************>>>", reg_num_list

        #vals = self.readCoreRegistersRaw(reg_num_list)
        #print("Vals: %s" % vals)
        #for reg, regValue in zip(self.register_list, vals): # XXX original
        for idx, reg in enumerate(self.register_list):
            #regName = self.register_list[reg].name
            regValue = self.emu.read_register(reg.name)
            #regValue = idx

            #resp += struct.pack("<Q", regValue).encode("hex") # conversion.intToHex8(regValue) # FIXME
            resp += struct.pack(">I", regValue).encode("hex") 
            #resp += conversion.intToHex16(regValue) # FIXME

            #self.logger.debug("GDB reg: %s = 0x%X", reg.name, regValue)

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
        #print len(data)/8
        #regs_values = struct.unpack(">" + "I" * (len(data)/8), data)
        #for i, value in enumerate(regs_values):
        for i, value in enumerate(xrange(0, len(data), 8)):
            value = int(data[i*8 : (i*8) + 8], 16)
            #self.logger.error("Idx 0x%X : 0x%X" % (i, value))
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
        return "T05" # TODO FIXME
        fmt = "<Q"
        fmt = ">I"
        
        resp = []
        resp.append("T0506:0 *,")

        regValue = 0x3344#self.emu.read_register("sp")
        enc_reg = struct.pack(fmt, regValue).encode("hex")
        resp.append("07:" + enc_reg)

        regValue = 0x1122#self.emu.read_register("pc")
        enc_reg = struct.pack(fmt, regValue).encode("hex")
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
