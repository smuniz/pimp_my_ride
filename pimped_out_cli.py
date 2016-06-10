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
import logging
from argparse import ArgumentParser

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

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

def get_gdb_server_settings(args):
    """Set GDB server settings."""
    return {
        #'break_at_hardfault' : args.break_at_hardfault,
        #'step_into_interrupt' : args.step_into_interrupt,
        #'break_on_reset' : args.break_on_reset,
        'persist' : args.persist,
        #'soft_bkpt_as_hard' : args.soft_bkpt_as_hard,
        #'chip_erase': get_chip_erase(args),
        #'hide_programming_progress' : args.hide_progress,
        #'fast_program' : args.fast_program,
        'port_number' : args.port_number,
    }

def setup_logging(args):
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)

def main():

    #supported_targets = pyOCD.target.TARGET.keys()
    debug_levels = LEVELS.keys()

    # Keep args in snyc with flash_tool.py when possible
    parser = ArgumentParser(description=__description__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument("-p", "--port", dest = "port_number", type=int, default = 3333, help = "Port number that GDB server will listen.")
    #parser.add_argument("-c", "--cmd-port", dest = "cmd_port", default = 4444, help = "Command port number. pyOCD doesn't open command port, but it's required to be compatible with OpenOCD and Eclipse.")
    #parser.add_argument("-b", "--board", dest = "board_id", default = None, help="Connect to board by board id.  Use -l to list all connected boards.")
    #parser.add_argument("-l", "--list", action = "store_true", dest = "list_all", default = False, help = "List all connected boards.")
    parser.add_argument("-d", "--debug", dest = "debug_level", choices = debug_levels, default = 'info', help = "Set the level of system logging output. Supported choices are: "+", ".join(debug_levels), metavar="LEVEL")
    #parser.add_argument("-n", "--nobreak", dest = "break_at_hardfault", default = True, action="store_false", help = "Disable halt at hardfault handler." )
    #parser.add_argument("-r", "--reset-break", dest = "break_on_reset", default = False, action="store_true", help = "Halt the target when reset." )
    #parser.add_argument("-s", "--step-int", dest = "step_into_interrupt", default = False, action="store_true", help = "Allow single stepping to step into interrupts." )
    #parser.add_argument("-f", "--frequency", dest = "frequency", default = 1000000, type=int, help = "Set the SWD clock frequency in Hz." )
    parser.add_argument("-o", "--persist", dest = "persist", default = False, action="store_true", help = "Keep GDB server running even after remote has detached.")
    parser.add_argument("-t", "--target", dest = "target", default = None, help = "target to debug.", metavar="TARGET", required=True)
    #parser.add_argument("-bh", "--soft-bkpt-as-hard", dest = "soft_bkpt_as_hard", default = False, action = "store_true", help = "Replace software breakpoints with hardware breakpoints.")
    #group = parser.add_mutually_exclusive_group()
    #group.add_argument("-ce", "--chip_erase", action="store_true",help="Use chip erase when programming.")
    #group.add_argument("-se", "--sector_erase", action="store_true",help="Use sector erase when programming.")
    ## -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked
    #parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock the device.")
    ## reserved: "-a", "--address"
    ## reserved: "-s", "--skip"
    #parser.add_argument("-hp", "--hide_progress", action="store_true", help = "Don't display programming progress." )
    #parser.add_argument("-fp", "--fast_program", action="store_true", help = "Use only the CRC of each page to determine if it already has the same data.")

    args = parser.parse_args()

    # Setup logging facility.
    setup_logging(args)

    # Setup GDB with user-specified settings.
    gdb_server_settings = get_gdb_server_settings(args)

    #
    # Obtain the memory ranges where we're going to operate.
    #
    image_filename = args.target

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

        board = PimpedOutBoard()

        print "[+] Initializing GDB server..."
        #gdb = GDBServer(board, gdb_server_settings)

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
