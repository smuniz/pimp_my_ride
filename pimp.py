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
__description__ = "Pimp Multi-architecture CPU Emulator"

#from __future__ import print_function
from sys import argv, exit
from traceback import format_exc

try:
    from elftools.elf.elffile import ELFFile
except ImportError, err:
    print "Missing 'pyelftools' module."
    exit(1)

try:
    import unicorn as uc
except ImportError, err:
    print "Missing 'unicorn engine' module."

from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.x86_const import *

try:
    import capstone as cs
except ImportError, err:
    print "Missing 'capstone engine' module."


#from idaapi import *

PPC_ARCH = 0
MIPS_ARCH = 1
ARM_ARCH = 2
X86_ARCH = 3
X86_64_ARCH = 4

PAGE_ALIGN = 0x1000 # 4k

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
        stack=0xf000000, ssize=3):

        self.__debug = True

        self.__uc = None  # Unicorn instance.

        self.__cs = None  # Capstone instance.

        # Emulation parameters.
        self.code = None
        self.return_address = None
        self.memory_address = None
        self.memory_length = None

        self.stack = self._alignAddr(stack)
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
                raise PimpMyRideException("Unknown {}bit for ARM architecture".format(bits))

        elif architecture == "pc":

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
                raise PimpMyRideException("Unknown {}bit for X86 architecture".format(bits))

        else:
            raise PimpMyRideException(
                "Unsupported architecture %s" % architecture)

        if self.__debug:
            print "[DBG] Architecture: {} {}bits".format(architecture, bits)

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

    @property
    def memory_address(self):
        """Return the initial memory address."""
        return self._memory_address

    @memory_address.setter
    def memory_address(self, memory_address):
        """Store the initial memory address."""
        self._memory_address = memory_address

    @property
    def memory_length(self):
        """Return the current memory length."""
        return self._memory_length

    @memory_length.setter
    def memory_length(self, memory_length):
        """Store the current memory length."""
        self._memory_length = memory_length

    @property
    def return_address(self):
        """Return the initial return address."""
        return self._return_address

    @return_address.setter
    def return_address(self, return_address):
        """Store the initial return address."""
        self._return_address = return_address

    def start(self):
        """Start the emulation phase with the parameters previously defined."""
        #
        # Initialize Unicorn's operational parameters.
        #
        if not self.code:
            raise PimpMyRideException("Code not specified")

        if not self.architecture:
            raise PimpMyRideException("Architecture not specified")

        if self.mode is None:
            raise PimpMyRideException("Mode not specified")

        if self.return_address is None:
            raise PimpMyRideException("Return address not specified")

        if self.memory_address is None:
            raise PimpMyRideException("Memory address not specified")

        if not self.memory_length:
            raise PimpMyRideException("Memory length not specified")

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

        #print "*" * 80
        #for i in self.__cs.disasm(self.code, self.memory_address):
        #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

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


    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def __initialize_memory(self):
        """Initialize the emulator memory with the appropriate ranges and
        contents.
        
        """
        if self.__debug:
            print "[DBG] Memory address : 0x%08X (%dMb)" % (
                self.memory_address, self.memory_length/1024/1024)

        stack_size = (self.ssize+1) * PAGE_ALIGN

        self._mem_map(self.stack, stack_size)
        self._mem_write(self.stack, "\x00" * stack_size)

        sp = self.stack + self.ssize * PAGE_ALIGN
        self.__uc.reg_write(self.REG_SP, sp)

        addr = self._alignAddr(self.memory_address)
        size = self.memory_length * 2 # FIXME

        self._mem_map(addr, size, uc.UC_PROT_ALL)#self.memory_length)
        self._mem_write(self.code[1], self.code[0])

        print "%r" % self.__uc.mem_read(self.memory_address, 0x10)

    def _mem_write(self, addr, data):
        print "[DBG] Writting 0x%08X (size 0x%X)" % (addr, len(data))
        self.__uc.mem_write(addr, data)

    def _mem_map(self, addr, size, perm=None):
        print "[DBG] Mapping 0x%08X - 0x%08X (size 0x%X)" % (addr, addr + size, size)
        if perm:
            self.__uc.mem_map(addr, size, perm)
        else:
            self.__uc.mem_map(addr, size)

    def _get_bit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _show_regs(self):
        print(">>> regs:")
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

                print("    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                print("    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                print("    IP = 0x%x" % eip)     

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

                print("    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                print("    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                print("    EIP = 0x%x" % eip)

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

                print("    RAX = 0x%016x RBX = 0x%016x RCX = 0x%016x RDX = 0x%016x" % (rax, rbx, rcx, rdx))
                print("    RDI = 0x%016x RSI = 0x%016x RBP = 0x%016x RSP = 0x%016x" % (rdi, rsi, rbp, rsp))
                print("    R$8 = 0x%016x R9  = 0x%016x R10 = 0x%016x R11 = 0x%016x" % (r8, r9, r10, r11))
                print("    R12 = 0x%016x R13 = 0x%016x R14 = 0x%016x R15 = 0x%016x" % (r12, r13, r14, r15))
                print("    RIP = 0x%016x" % rip)
            print("    EFLAGS:")
            print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
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
            print("#ERROR: %s" % e)


    def __initialize_hooks(self):
        """..."""
        # Add code hooks (if any).
        for hook, cb in self.__hooks.iteritems():
            if self.__debug:
                print "[DBG] Adding hook %s" % cb
            self.__uc.hook_add(hook, cb)

    def __initialize_registers(self):
        """..."""
        for reg, value in self.__regs.iteritems():
            self.__uc.reg_write(reg, value)

    def __emulate(self):
        """..."""
        try:
            timeout = 0
            count = 0

            self.__uc.emu_start(self.memory_address,
                                self.return_address,
                                timeout,
                                count)
        except uc.UcError, err:
            if self.__debug:
                print "[DBG] Emulation error : %s" % err
                #print format_exc()
            self._show_regs()
            raise PimpMyRideException(err)

    def add_code_hook(self, callback_fn):
        """..."""
        self.__hooks[uc.UC_HOOK_CODE] = callback_fn

    def write_register(self, register, value):
        """..."""
        self.__regs[register] = value

    def result(self):
        """Return the emulation results (if any)."""
        # TODO : Check weather register constant name is correct or not.
        #print "$v0 = 0x%08X" % self.__uc.reg_read(UC_MIPS_REG_V0)
        self._show_regs()

    def _show_disasm_inst(self, opcodes, addr):
        """..."""
        print ""
        for i in self.__cs.disasm(str(opcodes), addr):
            print "    0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)

    # callback for tracing instructions
    def hook_code(self, _uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
        try:
            self._show_regs()

            opcodes = _uc.mem_read(address, size)
            self._show_disasm_inst(opcodes, address)
            print ""
        #except Exception, err:
        except uc.UcError as err:
            print "Error on code hook: %s" % err

        #uc.uc_emu_stop()
        #raise Exception("I want to stop!!!")

# callback for tracing invalid memory access (READ or WRITE, FETCH)
def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
    # TODO
    print "[HOOK] Memory access invalid at 0x%08X" % address

def _autodetect_architecture():
    """Detect the current architecture in use by the disassembler being
    used.
    
    """
    #architecture = get_idp_name()
    architecture = "pc"
    bits = 64 # FIXME

    #info = get_inf_structure()

    #if info.is_64bit():
    #    bits = 64
    #elif info.is_32bit():
    #    bits = 32
    #else:
    #    bits = 16

    endian = None # TODO : implement with last letter of info.procName
    return (architecture, bits, endian)

def main():

    #
    # Obtain the memory ranges where we're going to operate.
    #
    #fn = get_func(ScreenEA())
    #mem_address = fn.startEA
    #mem_length = 2 * 1024 * 1024
    image_filename = argv[1]

    fd = open(image_filename, 'rb')
    image = ELFFile(fd)

    # FIXME
    #mem_address = 0x4004D6 # image.header['e_entry']
    mem_address = 0x04004FD
    mem_length = 4 * PAGE_ALIGN

    #refs = [ref.frm for ref in XrefsTo(fn.startEA, 0)]

    #if len(refs) == 0:

    #    print("[-] Unable to find a return address. Quitting...")
    #    return

    #ret_address = refs[0] + ItemSize(refs[0])
    ret_address = 0x400502

    #
    # Read the code to emulate
    #
    #code = GetManyBytes(fn.startEA, fn.endEA - fn.startEA) # FIXME : Only reads current func
    #code = "\x34\x21\x34\x56" # ori $at, $at, 0x3456;
    addr = image.get_section_by_name(".text").header.sh_addr
    code = image.get_section_by_name(".text").data()
    #print ["%02X" % ord(b) for b in code]

    if not code:
        print "[-] Unable to obtain opcodes to emulate. Quitting..."
        return

    #
    # Set architecture specific types for the current binary being
    # analyzed.
    #
    architecture, bits, endian = _autodetect_architecture()

    #
    # Initialize the emulator and set the operational parameters.
    #
    print "[+] Configuring emulator..."
    emu = PimpMyRide(architecture, bits, endian)

    emu.code = (code, addr)
    emu.memory_address = mem_address
    emu.memory_length = mem_length
    emu.return_address = ret_address

    # tracing all instructions with customized callback
    emu.add_code_hook(emu.hook_code)

    print "[+] Initiating emulation..."
    emu.start()

    print "[+] Emulation finished."
    emu.result()

if __name__ == "__main__":
    print "%s v%s\n" % (__description__, __version__)

    main()
