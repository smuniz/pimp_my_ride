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

from sys import argv, exit

from pimp_my_ride import *

try:
    from elftools.elf.elffile import ELFFile
except ImportError, err:
    print "Missing 'pyelftools' module."
    exit(1)

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

def usage():
    """Print usage information."""
    print "Usage: %s [FILE]" % argv[0]
    
def main():

    if len(argv) == 1:
        usage()
        exit(1)

    #
    # Obtain the memory ranges where we're going to operate.
    #
    #fn = get_func(ScreenEA())
    #mem_address = fn.startEA
    #mem_length = 1 * 1024 * 1024
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
    addr = image.get_section_by_name(".text").header.sh_addr
    code = image.get_section_by_name(".text").data()

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
