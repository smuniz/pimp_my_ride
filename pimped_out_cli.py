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

try:
    from pimp_my_ride import *
except ImportError, err:
    print "[-] Import Error : %s" % err
    exit(1)

#from idaapi import *

from target import Target
#from board import Board
from gdb_server import GDBServer

__all__ = ["Pimped"]

class PimpedOutTarget(Target):

    def __init__(self):
        super(PimpedOutTarget, self).__init__(None)


# Find a connected mbed device
class PimpedOutBoard(object):

    def __init__(self):
        super(PimpedOutBoard, self).__init__()
        self.target = PimpedOutTarget()

    def init(self):
        """
        Initialize the board: interface, transport and target
        """
        pass

    def uninit(self, resume = True ):
        """
        Uninitialize the board: interface, transport and target.
        This function resumes the target
        """
        pass

try:
    from elftools.elf.elffile import ELFFile

    from elftools.elf.descriptions import (
        describe_ei_class, describe_ei_data, describe_ei_version,
        describe_ei_osabi, describe_e_type, describe_e_machine,
        describe_e_version_numeric, describe_p_type, describe_p_flags,
        describe_sh_type, describe_sh_flags,
        describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
        describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
        describe_ver_flags, describe_note
        )

except ImportError, err:
    print "Missing 'pyelftools' module."
    exit(1)

def autodetect_architecture(image):
    """Detect the current architecture in use by the disassembler being
    used.
    
    """
    architecture = image.get_machine_arch()
    bits = image.elfclass
    little_endian = image.little_endian

    return (architecture, bits, little_endian)

def setup_logging(args):
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)

def usage():
    """Print usage information."""
    print "Usage: %s [FILE]" % argv[0]
    
def main():

    if len(argv) == 1:
        usage()
        return

    #
    # Obtain the memory ranges where we're going to operate.
    #
    image_filename = argv[1]

    try:
        fd = open(image_filename, 'rb')
    except IOError, err:
        print "[-] Invalid filename specified"
        return

    image = ELFFile(fd)

    # FIXME : automate this
    #start_address = 0x4004D6 # image.header['e_entry']
    start_address = 0x04004FD

    #fn = get_func(ScreenEA())
    #mem_address = fn.startEA
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
    architecture, bits, little_endian = autodetect_architecture(image)

    #
    # Initialize the emulator and set the operational parameters.
    #
    print "[+] Configuring emulator..."
    emu = PimpMyRide(architecture, bits, little_endian)

    emu.add_memory_area(addr, len(code))
    emu.add_memory_content(addr, code)

    emu.start_address = start_address
    emu.return_address = ret_address

    # Tracing all instructions with internal callback.
    emu.trace_instructions()

    gdb = None

    try:
        print "[+] Initiating emulation..."
        emu.start()

        print "[+] Emulation finished."
        emu.result()

        #args = parser.parse_args()
        #gdb_server_settings = get_gdb_server_settings(args)
        #setup_logging(args)

        board = PimpedOutBoard()

        print "[+] Initializing GDB server..."
        #gdb = GDBServer(board, 3333)

        #while gdb.isAlive():
        #    gdb.join(timeout=0.5)

    except PimpMyRideException, err:
        print "[-] Error : %s" % err
        return

    except KeyboardInterrupt:
        pass

    except Exception as e:
        print "[-] Uncaught exception : %s" % e
        traceback.print_exc()

    finally:
        if gdb is not None:
            gdb.stop()

if __name__ == "__main__":
    print "%s v%s\n" % (__description__, __version__)

    main()
