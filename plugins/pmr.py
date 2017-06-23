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

# IDA < 6.9 support
if IDA_SDK_VERSION < 690:
  from PySide import QtGui, QtCore
  from PySide.QtGui import QTextEdit, QTableWidget, QTreeWidget, QCheckBox
  QtWidgets = QtGui
  USE_PYQT5 = False
else:
  from PyQt5 import QtGui, QtCore, QtWidgets
  from PyQt5.QtWidgets import QTextEdit, QTableWidget, QTreeWidget, QCheckBox
  USE_PYQT5 = True

try:
  import matplotlib.pyplot as plt
  import matplotlib.ticker as ticker

  if USE_PYQT5:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
  else:
    from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt4agg import NavigationToolbar2QT as NavigationToolbar
  from matplotlib.backend_bases import key_press_handler  
except ImportError:
  ERROR_MATPLOTLIB = True

PLUG_NAME    = "Pimp My Ride"
PLUG_VERSION = "v0.1"

def log(msg):
  Message("[%s] %s\n" % (PLUG_NAME, msg))

def get_ida_bytes(start_addr, end_addr, debug_memory):
  bytes = ""
  read_byte = Byte
  if debug_memory:
    read_byte = DbgByte

  try:
    # Another more efficient way to prevent section size aligment in IDB?
    c_addr = start_addr
    while c_addr < end_addr:
      if isLoaded(c_addr):
        bytes += chr(read_byte(c_addr))
      c_addr += 1

  except Exception, e:
    warning("Error reading data: %s" % e)
    return None
  return bytes 

def get_data(config):
  data = ""
  if config.disk_binary:
    with open(GetInputFilePath(), 'rb') as f:
      data = f.read()
  else:
    data = get_ida_bytes(config.start_addr, config.end_addr, config.debug_memory)
  if data:
    return data
  return None

class Config:
  def __init__(self):
    self.chart_type   = 0
    self.start_addr   = 0
    self.end_addr     = 0
    self.chart_type   = 0
    self.block_size   = 256
    self.disk_binary  = False
    self.debug_memory = False
    self.byte_entropy = False
    self.chart_types  = ["Histogram", "Entropy"]

class Options(QtWidgets.QWidget):
  def __init__(self, parent):
    QtWidgets.QWidget.__init__(self)
    self.parent = parent
    self.config = parent.config
    self.name = "Options"
    self.create_gui()

  #def chart_type_on_click(self):
  #  if not self.update_addrs():
  #    warning("Invalid address")
  #    return
  #  try:
  #    show_wait_box("Making chart...")
  #    data = get_data(self.config)
  #    if not data:
  #      hide_wait_box()
  #      warning("There's no data to make the chart")
  #      return
  #    if self.config.chart_type == ChartType.ENTROPY:       
  #      self.parent.tabs.addTab(Entropy(self, data), self.get_tab_title())
  #    elif self.config.chart_type == ChartType.HISTOGRAM:
  #      self.parent.tabs.addTab(Histogram(self, data), self.get_tab_title())
  #    del data
  #  except Exception, e:
  #    warning("%s" % e)
  #  hide_wait_box()    

  #def get_tab_title(self):
  #  i_type = self.config.chart_type
  #  title = self.config.chart_types[i_type] + " - "
  #  if self.config.disk_binary:
  #    title += "Disk binary"
  #  else:
  #    segname = SegName(self.config.start_addr)
  #    if segname:
  #      title += "%s " % segname
  #    title += "[0x%08x - 0x%08x]" % (self.config.start_addr, self.config.end_addr)
  #  return title

  def create_gui(self):
    self.t_start_addr    = QtWidgets.QLineEdit(self)
    self.t_end_addr      = QtWidgets.QLineEdit(self)
    self.cb_section      = QtWidgets.QComboBox(self)
    self.cb_disk_bin     = QtWidgets.QCheckBox(self)
    self.cb_debug_memory = QtWidgets.QCheckBox(self)
    button_chart         = QtWidgets.QPushButton("Chart")

    self.t_start_addr.setFixedWidth(200)
    self.t_end_addr.setFixedWidth(200)
    self.cb_section.setFixedWidth(200)
    button_chart.setFixedWidth(50)

    self.fill_sections()

    form = QtWidgets.QFormLayout()
    form.addRow("Start address:", self.t_start_addr)
    form.addRow("End address:", self.t_end_addr)
    form.addRow("Section:", self.cb_section)
    form.addRow("Disk binary:", self.cb_disk_bin)
    form.addRow("Debug memory:", self.cb_debug_memory)
    #form.addRow("Chart type:", self.create_chart_type_group())
    form.addRow(button_chart)

    self.cb_section.currentIndexChanged[int].connect(self.cb_section_changed)
  #  self.cb_disk_bin.stateChanged.connect(self.cb_changed)
  #  self.cb_debug_memory.toggled.connect(self.cb_changed)
  #  button_chart.clicked.connect(self.chart_type_on_click)

    self.setLayout(form)

  #def cb_changed(self, state):
  #  sender = self.sender()

  #  if sender is self.cb_disk_bin:    
  #    checked = (state == QtCore.Qt.Checked)  
  #    self.config.disk_binary = checked
  #    b_enabled = not checked

  #    self.t_start_addr.setEnabled(b_enabled)
  #    self.t_end_addr.setEnabled(b_enabled)
  #    self.cb_section.setEnabled(b_enabled)
  #    self.cb_debug_memory.setEnabled(b_enabled)

  #  elif sender is self.cb_debug_memory:
  #    if idaapi.is_debugger_on():
  #      self.config.debug_memory = state
  #    else:
  #      warning("The debugger is not running")
  #      block = sender.blockSignals(True)
  #      sender.setChecked(False)
  #      sender.blockSignals(block)

  def is_not_xtrn_seg(self, s_ea):
    if GetSegmentAttr(s_ea, SEGATTR_TYPE) != SEG_XTRN:
      return True
    return False

  def fill_sections(self):
    segments = filter(self.is_not_xtrn_seg, Segments()) 

    for idx, s_ea in enumerate(segments):
      if idx == 0:
        self.set_addrs(SegStart(s_ea), SegEnd(s_ea))
      self.cb_section.addItem(SegName(s_ea), s_ea)

    if not segments:
      self.set_addrs(0 ,0)
      self.cb_section.setEnabled(False)

  #def create_chart_type_group(self):
  #  vbox = QtWidgets.QVBoxLayout()
  #  self.rg_chart_type = QtWidgets.QButtonGroup()
  #  self.rg_chart_type.setExclusive(True)

  #  for i, choice in enumerate(self.config.chart_types):
  #    radio = QtWidgets.QRadioButton(choice)
  #    self.rg_chart_type.addButton(radio, i)
  #    if i == self.config.chart_type: 
  #      radio.setChecked(True)
  #    vbox.addWidget(radio)

  #  vbox.addStretch(1)
  #  self.rg_chart_type.buttonClicked.connect(self.bg_graph_type_changed)
  #  return vbox

  #def bg_graph_type_changed(self, radio):
  #  self.config.chart_type = self.rg_chart_type.checkedId()

  def cb_section_changed(self, value):
    sender = self.sender()
    s_ea = sender.itemData(value)
    start_addr = SegStart(s_ea)
    end_addr   = SegEnd(s_ea)
    self.set_addrs(start_addr, end_addr)

  def set_addrs(self, start_addr, end_addr):
    self.t_start_addr.setText("0x%x" % start_addr)
    self.t_end_addr.setText("0x%x" % end_addr)
    self.config.start_addr = start_addr
    self.config.end_addr = end_addr

  #def update_addrs(self):
  #  try:
  #    self.config.start_addr = int(self.t_start_addr.text(), 16)
  #    self.config.end_addr   = int(self.t_end_addr.text(), 16)
  #    return True
  #  except ValueError:
  #    return False

class PimpMyRideForm(PluginForm):
  def __init__(self):
    super(PimpMyRideForm, self).__init__()
    self.config = Config()

    # disable timeout for scripts
    self.old_timeout = idaapi.set_script_timeout(0)

  def OnCreate(self, form):
    if USE_PYQT5:
      self.parent = self.FormToPyQtWidget(form)
    else:
      self.parent = self.FormToPySideWidget(form)
    self.PopulateForm()

  def RemoveTab(self, index):
    pass

  def PopulateForm(self):
    layout = QtWidgets.QVBoxLayout()

    self.tabs = QtWidgets.QTabWidget()
    self.tabs.setMovable(True)
    self.tabs.setTabsClosable(True)
    self.tabs.tabCloseRequested.connect(self.remove_tabs)
    self.tabs.addTab(Options(self), "Options")
    layout.addWidget(self.tabs)
    self.parent.setLayout(layout)

  def remove_tabs(self, index):
    if not isinstance(self.tabs.widget(index), Options):
      self.tabs.removeTab(index)

  def OnClose(self, form):
    idaapi.set_script_timeout(self.old_timeout)
    print "[%s] Form closed." % PLUG_NAME

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
      plg = PimpMyRideForm().Show(PLUG_NAME)
  except Exception, err:
      print print_exc()

