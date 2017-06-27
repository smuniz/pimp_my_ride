#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Pimp My Ride
#  22/06/2017
#
#  Sebastian Muniz <sebastianmuniz [at] gmail.com>
#  @_topo
# 
from traceback import print_exc

from idc import *
from idaapi import *
from idautils import *

#from pimp_my_ride.pmr_form import PimpMyRideForm

PLUG_NAME    = "Pimp My Ride"
PLUG_VERSION = "v0.1"

def log(msg):
  Message("[%s] %s\n" % (PLUG_NAME, msg))

class PimpMyRide_t(plugin_t):
    flags = PLUGIN_UNL
    comment = "Multiarch emulator"
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = "Ctrl-5"

    def init(self):
        self.icon_id = 0
        return PLUGIN_OK

    def run(self, arg=0):
        #f = PimpMyRideForm()
        #f.Show(PLUG_NAME)
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return PimpMyRide_t()

if __name__ == '__main__':
  log("Plugin loaded")
  try:
      #plg = PimpMyRideForm().Show(PLUG_NAME)
  except Exception, err:
      print print_exc()
