"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

from pyOCD.target import TARGET
from pyOCD.transport import TRANSPORT
from pyOCD.flash import FLASH

import logging

class Board(object):
    """
    This class associates a target, a flash, a transport and an interface
    to create a board
    """
    def __init__(self, target, flash, transport, frequency = 1000000):
        self.transport = transport
        self.target = TARGET[target](self.transport)
        self.flash = FLASH[flash](self.target)
        self.target.setFlash(self.flash)
        self.debug_clock_frequency = frequency
        self.closed = False
        return
        
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.uninit()
        return False
    
    def init(self):
        """
        Initialize the board: interface, transport and target
        """
        logging.debug("init board %s", self)
        self.transport.init(self.debug_clock_frequency)
        packet_count = self.getPacketCount()
        logging.info("board allows %i concurrent packets", packet_count)
        if packet_count < 1:
            logging.error('packet count of %i outside of expected range', packet_count)
            packet_count = 1
        self.transport.setPacketCount(packet_count)
        self.target.init()
        
    def uninit(self, resume = True ):
        """
        Uninitialize the board: interface, transport and target.
        This function resumes the target
        """
        if self.closed:
            return
        self.closed = True
            
        logging.debug("uninit board %s", self)
        if resume:
            try:
                self.target.resume()
            except:
                logging.error("exception during uninit")
                pass
        self.transport.uninit()

    def getInfo(self):
        return ('%s %s (%04x:%04x:%x)' %
                (self.transport.vendor_name,
                 self.transport.product_name,
                 self.transport.vid,
                 self.transport.pid,
                 self.transport.iid))

    def getPacketCount(self):
        """
        Return the number of commands the remote device's buffer can hold.
        """
        return 1
