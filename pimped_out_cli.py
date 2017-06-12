#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__       = "Sebastian 'topo' Muniz"
__copyright__   = "Copyright 2016"
__credits__     = []
__license__     = "GPL"
__version__     = "0.1"
__maintainer__  = "Sebastian Muniz"
__email__       = "sebastianmuniz@gmail.com"
__status__      = "Development"
__description__ = "Pimped out multi-architecture CPU emulator"

from sys import argv, exit
from argparse import ArgumentParser
from traceback import print_exc
import logging

try:
    from pimp_my_ride import *

    from target.board import Board
    from target.emulated_target import EmulatedTargetX86_64
    from target.emulated_target_mips import EmulatedTargetMips
    from gdbserver.gdb_server import GDBServer

except ImportError, err:
    print "Import Error : %s" % err
    exit(1)

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

__all__ = ["Pimped"]

def autodetect_architecture(image):
    """Detect the current architecture in use by the disassembler being
    used.
    
    """
    architecture = image.get_machine_arch()
    bits = image.elfclass
    is_little_endian = image.little_endian

    return (architecture, bits, is_little_endian)

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
        'port_urlWSS' : args.port_number,
        'log_level' : LOG_LEVELS.get(args.log_level),
    }

def main():

    log_levels = LOG_LEVELS.keys()

    parser = ArgumentParser(description=__description__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument("-p", "--port", dest = "port_number", type=int, default = 3333, help = "Port number that GDB server will listen.")
    #parser.add_argument("-c", "--cmd-port", dest = "cmd_port", default = 4444, help = "Command port number. pyOCD doesn't open command port, but it's required to be compatible with OpenOCD and Eclipse.")
    #parser.add_argument("-b", "--board", dest = "board_id", default = None, help="Connect to board by board id.  Use -l to list all connected boards.")
    #parser.add_argument("-l", "--list", action = "store_true", dest = "list_all", default = False, help = "List all connected boards.")
    parser.add_argument("-l", "--log-level", dest = "log_level", choices = log_levels, default = 'info', help = "Set the level of system logging output. Supported choices are: "+", ".join(log_levels), metavar="LEVEL")
    #parser.add_argument("-n", "--nobreak", dest = "break_at_hardfault", default = True, action="store_false", help = "Disable halt at hardfault handler." )
    #parser.add_argument("-r", "--reset-break", dest = "break_on_reset", default = False, action="store_true", help = "Halt the target when reset." )
    #parser.add_argument("-s", "--step-int", dest = "step_into_interrupt", default = False, action="store_true", help = "Allow single stepping to step into interrupts." )
    #parser.add_argument("-f", "--frequency", dest = "frequency", default = 1000000, type=int, help = "Set the SWD clock frequency in Hz." )
    parser.add_argument("-o", "--persist", dest = "persist", default = False, action="store_true", help = "Keep GDB server running even after remote has detached.")
    parser.add_argument("-t", "--target", dest = "target", default = None, help = "Target filename to emulate.", metavar="TARGET", required=True)
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

    # Setup logging facility and GDB server settings.
    #setup_logging(args)
    gdb_server_settings = get_gdb_server_settings(args)

    try:
        fd = open(args.target, 'rb')
    except IOError, err:
        print "Error : Invalid filename (%s) specified." % args.target
        return

    image = ELFFile(fd)

    #
    # Obtain the memory ranges where we're going to operate.
    #
    start_address = 0x004007e8 #image.header.e_entry
    #start_address = 

    ret_address = 0x0400810 #0x400502

    #
    # Read the code to emulate
    #
    dot_text = image.get_section_by_name(".text")

    addr = dot_text.header.sh_addr
    code = dot_text.data()

    if not code or len(code) is 0:
        print "[-] Unable to obtain codes to emulate. Quitting..."
        return

    emu = None
    gdb = None

    try:
        # Set architecture specific types for the current binary being
        # analyzed.
        architecture, bits, is_little_endian = autodetect_architecture(image)

        # Initialize the emulator and set the operational parameters.
        print "[+] Configuring emulator..."
        emu = PimpMyRide(architecture, bits, is_little_endian,
                log_level=LOG_LEVELS.get(args.log_level))

        emu.add_memory_area(addr, len(code))
        emu.add_memory_content(addr, code)

        emu.start_address = start_address
        emu.return_address = ret_address

        # Set tracing all instructions with internal callback.
        emu.trace_instructions()

        #board = Board(EmulatedTargetX86_64(emu))
        board = Board(EmulatedTargetMips(emu))

        print "[+] Initializing GDB server..."
        gdb = GDBServer(board, gdb_server_settings)

        while gdb.isAlive():
            gdb.join(timeout=0.5)

    except PimpMyRideException, err:
        print "[-] Error : %s" % err
        return

    except KeyboardInterrupt:
        print "\n[+] Termination requested..."

    except Exception as e:
        print "[-] Uncaught exception : %s" % e
        print_exc()

    finally:
        if gdb is not None:
            gdb.stop()

if __name__ == "__main__":
    print "%s v%s\n" % (__description__, __version__)

    main()
