#!/usr/bin/env python
# -*- coding: utf-8 -*-
_author__       = "Sebastian 'topo' Muniz"
__copyright__   = "Copyright 2016, Recurity Labs GmbH"
__credits__     = []
__license__     = "GPL"
__version__     = "0.1"
__maintainer__  = "Sebastian Muniz"
__email__       = "sebastianmuniz@gmail.com"
__status__      = "Development"
__description__ = "Pimped out multi-architecture CPU emulator"

from traceback import format_exc
import logging

logging.basicConfig(level=logging.DEBUG)

try:
    import unicorn as uc
except ImportError, err:
    logging.critical("Missing 'unicorn engine' module.")
    raise ImportError(err)

from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.x86_const import *

try:
    import capstone as cs
except ImportError, err:
    logging.critical("Missing 'capstone engine' module.")

__all__ = ["PimpMyRide", "PimpMyRideException"]

#
# List of supported architectures
#
PPC_ARCH = 0
MIPS_ARCH = 1
ARM_ARCH = 2
X86_ARCH = 3
X86_64_ARCH = 4

PAGE_SIZE = 0x1000 # Default page size is 4KB

COMPILE_GCC = 0
COMPILE_MSVC = 1


class PimpMyRideException(Exception):
    """Generic exception for PimpMyRide."""
    pass


class PimpMyRide(object):
    """
    Main class implementing the multi-architecture CPU emulator with debugging
    support.
    
    """

    def __init__(self, architecture, bits, endian, compiler=COMPILE_GCC, \
        stack=0xf000000, ssize=3, debug=True):

        logging.basicConfig(level=logging.DEBUG)

        self.__uc = None  # Unicorn instance.

        self.__cs = None  # Capstone instance.

        # Emulation parameters.
        self.code = None
        self.start_address = None
        self.return_address = None

        self.__memory_areas = []
        self.__memory_contents = []

        self.stack = self._align_address(stack)
        self.ssize = ssize

        self.compiler = compiler


        # Convert IDA architectures IDs to our own.
        if architecture == "ppc":
            raise PimpMyRideException("PowerPC is unsupported.")

        elif architecture == "mips":
            #import unicorn.mips_const import *

            #cur_arch = uc.UC_ARCH_MIPS
            #cur_mode = uc.UC_MODE_MIPS32 + uc.UC_MODE_BIG_ENDIAN

            raise PimpMyRideException("MIPS is not yet implemented.")

        elif architecture == "arm":
            if bits == 64:
                cur_arch = uc.UC_ARCH_ARM64
                cur_mode = uc.UC_MODE_ARM

            elif bits == 32:
                cur_arch = uc.UC_ARCH_ARM
                cur_mode = uc.UC_MODE_ARM

            else:
                raise PimpMyRideException(
                        "Unknown %dbit for ARM architecture" % bits)

        elif architecture == "x86":

            cur_arch = uc.UC_ARCH_X86
            cs_arch = cs.CS_ARCH_X86

            if bits == 64:
                cur_mode = uc.UC_MODE_64
                cs_mode = cs.CS_MODE_64
            elif bits == 32:
                cur_mode = uc.UC_MODE_32
                cs_mode = cs.CS_MODE_32
            elif bits == 16:
                cur_mode = uc.UC_MODE_16
                cs_mode = cs.CS_MODE_16
            else:
                raise PimpMyRideException("Unknown %dbit for X86 architecture" % bits)

        else:
            raise PimpMyRideException(
                "Unsupported architecture %s" % architecture)

        logging.debug("Architecture: %s %dbits" % (
                architecture.upper(), bits))

        self.architecture = cur_arch
        self.mode = cur_mode

        self._cs_arch = cs_arch
        self._cs_mode = cs_mode
        #self.instruction_set = current_arch.InstructionSet()

        self.__regs = dict()
        self.__hooks = dict()

    @property
    def code(self):
        """Return the current code under execution."""
        return self._code

    @code.setter
    def code(self, code):
        """Store the current code under execution."""
        self._code = code

    @property
    def architecture(self):
        """Return the current architecture under execution."""
        return self._arch

    @architecture.setter
    def architecture(self, arch):
        """Store the current architecture under execution."""
        self._arch = arch

    @property
    def mode(self):
        """Return the current mode under execution."""
        return self._mode

    @mode.setter
    def mode(self, mode):
        """Store the current mode under execution."""
        self._mode = mode

    def add_memory_content(self, address, content):
        """Add a code region for the code emulation."""
        # Add the areas as a tuple (addr, size) unless we can think of a better
        # way to do it.
        # TODO : Validate area is valid for current architecture
        if not len(content):
            raise PimpMyRideException(
                    "Invalid memory content size specified (%d)" % size)
        self.__memory_contents.append([address, content])

    def add_memory_area(self, address, size):
        """Add a memory region for the code emulation."""
        # Add the areas as a tuple (addr, size) unless we can think of a better
        # way to do it.
        # TODO : Validate area is valid for current architecture
        if size <= 0:
            raise PimpMyRideException(
                    "Invalid memory area size specified (%d)" % size)
        self.__memory_areas.append([address, size])

    @property
    def start_address(self):
        """Return the initial start address."""
        return self._start_address

    @start_address.setter
    def start_address(self, address):
        """Store the initial start address."""
        self._start_address = address

    @property
    def return_address(self):
        """Return the return address."""
        return self._return_address

    @return_address.setter
    def return_address(self, address):
        """Store the return address."""
        self._return_address = address

    def start(self):
        """Start the emulation phase with the parameters previously defined."""
        #
        # Initialize Unicorn's operational parameters.
        #
        if not self.architecture:
            raise PimpMyRideException("Architecture not specified")

        if self.mode is None:
            raise PimpMyRideException("Mode not specified")

        if self.start_address is None:
            raise PimpMyRideException("Return address not specified")

        if self.return_address is None:
            raise PimpMyRideException("Return address not specified")

        if not len(self.__memory_areas):
            raise PimpMyRideException("No memory areas specified")

        if not len(self.__memory_contents):
            raise PimpMyRideException("No memory contents specified")

        self.__uc = uc.Uc(self.architecture, self.mode) # create new Unicorn
                                                        # instance.

        self.__cs = cs.Cs(self._cs_arch, self._cs_mode) # create new Unicorn
                                                        # instance.

        # Setup the register configuration
        self._setup_registers()

        #
        # Initialize the emulator memory.
        #
        self.__initialize_memory()

        #
        # Inialize the emulator hooks.
        #
        self.__initialize_hooks()

        #
        # Inialize the emulated CPU registers.
        #
        self.__initialize_registers()

        #for i in self.__cs.disasm(self.code, self.memory_address):
        #    logging.debug("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        #
        # Proceed to the emulation phase.
        #
        self.__emulate()

    def _setup_registers(self):
        if self.architecture == uc.UC_ARCH_X86:
            if self.mode == uc.UC_MODE_16:
                self.step = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_PC
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.mode == uc.UC_MODE_32:
                self.step = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.mode == uc.UC_MODE_64:
                self.step = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, 
                            UC_X86_REG_R8, UC_X86_REG_R9]
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]

        elif self.architecture == uc.UC_ARCH_ARM:
            if self.mode == uc.UC_MODE_ARM:
                self.step = 4
                self.pack_fmt = '<I'
            elif self.mode == uc.UC_MODE_THUMB:
                self.step = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]

        elif self.architecture == uc.UC_ARCH_ARM64:
            self.step = 8 
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

    def _align_address(self, address):
        """Align the specified address to a page boundary."""
        return address // PAGE_SIZE * PAGE_SIZE

    def __initialize_memory(self):
        """Initialize the emulator memory with the appropriate ranges and
        contents.
        """
        # Initialize the stack memory.
        stack_size = (self.ssize+1) * PAGE_SIZE

        self._memory_map(self.stack, stack_size)
        self._memory_write(self.stack, "\x00" * stack_size)

        sp = self.stack + self.ssize * PAGE_SIZE
        self.__uc.reg_write(self.REG_SP, sp)

        # Iterate through all the memory areas specified to map them all and
        # write content to them if necessary.
        for address, size in self.__memory_areas:
            size = self._align_address(size) + PAGE_SIZE # FIXME : horrible kludge! Will break contignous sections.
            address_aligned = self._align_address(address)

            self._memory_map(address_aligned, size, uc.UC_PROT_ALL)

        # Add the content to every previously mapped memory area.
        # Iterate through all the memory areas specified to map them all and
        # write content to them if necessary.
        for address, content in self.__memory_contents:
            self._memory_write(address, content)

    def _memory_write(self, address, content):
        """Set the content of a memory area with user-defined content."""
        logging.debug("Writting %d(0x%X) bytes at 0x%08X" % (
            len(content), len(content), address))

        # This will fail is the memory area was not yet defined in Unicorn.
        self.__uc.mem_write(address, content)

    def _memory_map(self, address, size, perm=None):
        """Map the specified address to a new memory area."""
        # This function should not be called directrly. Use add_memory_area
        # instead.
        logging.debug("Mapping 0x%08X - 0x%08X (size 0x%X)" % (
            address, address + size, size))

        if perm:
            self.__uc.mem_map(address, size, perm)
        else:
            self.__uc.mem_map(address, size)

    def _get_bit(self, value, offset):
        """Get the specified bit value from a bigger number."""
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def __show_regs(self):
        """..."""
        logging.debug("Registers:")
        try:
            if self.mode == uc.UC_MODE_16:
                ax = self.__uc.reg_read(UC_X86_REG_AX)
                bx = self.__uc.reg_read(UC_X86_REG_BX)
                cx = self.__uc.reg_read(UC_X86_REG_CX)
                dx = self.__uc.reg_read(UC_X86_REG_DX)
                di = self.__uc.reg_read(UC_X86_REG_SI)
                si = self.__uc.reg_read(UC_X86_REG_DI)
                bp = self.__uc.reg_read(UC_X86_REG_BP)
                sp = self.__uc.reg_read(UC_X86_REG_SP)
                ip = self.__uc.reg_read(UC_X86_REG_PC)
                eflags = self.__uc.reg_read(UC_X86_REG_EFLAGS)

                logging.debug("    AX = 0x%04x BX = 0x%04x CX = 0x%04x DX = 0x%04x" % (ax, bx, cx, dx))
                logging.debug("    DI = 0x%04x SI = 0x%04x BP = 0x%04x SP = 0x%04x" % (di, si, bp, sp))
                logging.debug("    IP = 0x%04x" % eip)     

            elif self.mode == uc.UC_MODE_32:
                eax = self.__uc.reg_read(UC_X86_REG_EAX)
                ebx = self.__uc.reg_read(UC_X86_REG_EBX)
                ecx = self.__uc.reg_read(UC_X86_REG_ECX)
                edx = self.__uc.reg_read(UC_X86_REG_EDX)
                edi = self.__uc.reg_read(UC_X86_REG_ESI)
                esi = self.__uc.reg_read(UC_X86_REG_EDI)
                ebp = self.__uc.reg_read(UC_X86_REG_EBP)
                esp = self.__uc.reg_read(UC_X86_REG_ESP)
                eip = self.__uc.reg_read(UC_X86_REG_EIP)
                eflags = self.__uc.reg_read(UC_X86_REG_EFLAGS)

                logging.debug("    EAX = 0x%08x EBX = 0x%08x ECX = 0x%08x EDX = 0x%08x" % (eax, ebx, ecx, edx))
                logging.debug("    EDI = 0x%08x ESI = 0x%08x EBP = 0x%08x ESP = 0x%08x" % (edi, esi, ebp, esp))
                logging.debug("    EIP = 0x%08x" % eip)

            elif self.mode == uc.UC_MODE_64:
                rax = self.__uc.reg_read(UC_X86_REG_RAX)
                rbx = self.__uc.reg_read(UC_X86_REG_RBX)
                rcx = self.__uc.reg_read(UC_X86_REG_RCX)
                rdx = self.__uc.reg_read(UC_X86_REG_RDX)
                rdi = self.__uc.reg_read(UC_X86_REG_RSI)
                rsi = self.__uc.reg_read(UC_X86_REG_RDI)
                rbp = self.__uc.reg_read(UC_X86_REG_RBP)
                rsp = self.__uc.reg_read(UC_X86_REG_RSP)
                rip = self.__uc.reg_read(UC_X86_REG_RIP)
                r8 = self.__uc.reg_read(UC_X86_REG_R8)
                r9 = self.__uc.reg_read(UC_X86_REG_R9)
                r10 = self.__uc.reg_read(UC_X86_REG_R10)
                r11 = self.__uc.reg_read(UC_X86_REG_R11)
                r12 = self.__uc.reg_read(UC_X86_REG_R12)
                r13 = self.__uc.reg_read(UC_X86_REG_R13)
                r14 = self.__uc.reg_read(UC_X86_REG_R14)
                r15 = self.__uc.reg_read(UC_X86_REG_R15)
                eflags = self.__uc.reg_read(UC_X86_REG_EFLAGS)

                logging.debug("    RAX = 0x%016x RBX = 0x%016x RCX = 0x%016x RDX = 0x%016x" % (rax, rbx, rcx, rdx))
                logging.debug("    RDI = 0x%016x RSI = 0x%016x RBP = 0x%016x RSP = 0x%016x" % (rdi, rsi, rbp, rsp))
                logging.debug("    R$8 = 0x%016x R9  = 0x%016x R10 = 0x%016x R11 = 0x%016x" % (r8, r9, r10, r11))
                logging.debug("    R12 = 0x%016x R13 = 0x%016x R14 = 0x%016x R15 = 0x%016x" % (r12, r13, r14, r15))
                logging.debug("    RIP = 0x%016x" % rip)

            logging.debug("    EFLAGS:")
            logging.debug("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                    "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                    % (self._get_bit(eflags, 0),
                       self._get_bit(eflags, 2),
                       self._get_bit(eflags, 4),
                       self._get_bit(eflags, 6),
                       self._get_bit(eflags, 7),
                       self._get_bit(eflags, 8),
                       self._get_bit(eflags, 9),
                       self._get_bit(eflags, 10),
                       self._get_bit(eflags, 11),
                       self._get_bit(eflags, 12) + self._get_bit(eflags, 13) * 2,
                       self._get_bit(eflags, 14),
                       self._get_bit(eflags, 16),
                       self._get_bit(eflags, 17),
                       self._get_bit(eflags, 18),
                       self._get_bit(eflags, 19),
                       self._get_bit(eflags, 20),
                       self._get_bit(eflags, 21)))

        except uc.UcError as e:
            #logging.debug("Exception: %s" % e)
            raise PimpMyRideException(e)

    def __initialize_hooks(self):
        """Commit all the hooks specified by the user."""
        # Add code hooks (if any).
        for hook, cb in self.__hooks.iteritems():
            logging.debug("Adding CODE hook : %s" % cb)
            self.__uc.hook_add(hook, cb)

        #TODO Add more hooks

    def __initialize_registers(self):
        """Set the registers to the user-specified values before the emulation
            starts.
        """
        for reg, value in self.__regs.iteritems():
            self.__uc.reg_write(reg, value)

    def __emulate(self):
        """Start the emulation and process results."""
        try:
            timeout = 0
            count = 0

            self.__uc.emu_start(self.start_address,
                                self.return_address,
                                timeout,
                                count)

        except uc.UcError, err:
            logging.debug("Emulation error : %s" % err)
                #logging.debug(format_exc())

            self.__show_regs()

            raise PimpMyRideException(err)

    def write_register(self, register, value):
        """Write the specified value into the specified regiuster."""
        self.__regs[register] = value

    def result(self):
        """Return the emulation results (if any)."""
        self.__show_regs()

    def _show_disasm_inst(self, opcodes, addr):
        """..."""
        try:
            for i in self.__cs.disasm(str(opcodes), addr):
                logging.info("    %s 0x%x:\t%s\t%s" % (
                        " ".join(
                            ["%02X" % ord(x) for x in str(i.bytes)]), i.address, i.mnemonic, i.op_str))
        except cs.CsError, err:
            raise PimpMyRideException(e)

    def add_code_hook(self, callback_fn):
        """Store user-specified callback function for the instruction tracing."""
        self.__hooks[uc.UC_HOOK_CODE] = callback_fn

    def trace_instructions(self):
        """Request the emulator to trace every executed instruction."""
        # TODO Enhance this code to differentiate internal callback from
        # user-defined hooks.
        logging.debug("Internal code trace enabled.")
        self.add_code_hook(self.__code_callback)

    def __code_callback(self, _uc, address, size, user_data):
        """Built-in callback for instructions tracing."""
        logging.debug("Tracing instruction at 0x%x, instruction size = %u" %(address, size))
        try:
            self.__show_regs()

            opcodes = _uc.mem_read(address, size)

            logging.info("")
            self._show_disasm_inst(opcodes, address)
            logging.info("")

            # TODO : call user-defined function now?
        except uc.UcError as err:
            logging.error("Error (CODE hook): %s" % err)

    def __memory_access_invalid_callback(self, uc, access, address, size, value, user_data):
        """Built-in callback for invalid memory accesses (READ or WRITE, FETCH)"""
        try:
            # FIXME : finish this
            logging.debug("Memory access invalid at 0x%08X" % address)

            # TODO : call user-defined function now?
        except uc.UcError as err:
            logging.error("Error (MEMORY hook): %s" % err)

