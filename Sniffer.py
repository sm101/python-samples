from __future__ import print_function
import  os
import  socket
import  ctypes
from scapy.all import *
# Derived from https://github.com/zeigotaro/python-sniffer, mostly
# python2 backport

###
# ifreq struct

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]
###
# flags for posix - no enums < python3.4

class FLAGS(object):
  # linux/if_ether.h
  ETH_P_ALL     = 0x0003 # all protocols
  ETH_P_IP      = 0x0800 # IP only
  # linux/if.h
  IFF_PROMISC   = 0x100
  # linux/sockios.h
  SIOCGIFFLAGS  = 0x8913 # get the active flags
  SIOCSIFFLAGS  = 0x8914 # set the active flags

###
# a platform-indep socket manager

class PromiscuousSocketManager(object): 
  def __init__(self, ifcname):
    if os.name == 'posix':
      import fcntl # posix-only
      # htons: converts 16-bit positive integers from host to network byte order
      s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))
      s.bind((ifcname, FLAGS.ETH_P_ALL))
      ifr = ifreq()
      ifr.ifr_ifrn = ifcname #TODO: make that a command line argument?
      fcntl.ioctl(s, FLAGS.SIOCGIFFLAGS, ifr) # get the flags
      ifr.ifr_flags |= FLAGS.IFF_PROMISC # add the promiscuous flag
      fcntl.ioctl(s, FLAGS.SIOCSIFFLAGS, ifr) # update
      self.ifr = ifr
    else:
      # the public network interface
      HOST = socket.gethostbyname(socket.gethostname())

      # create a raw socket and bind it to the public interface
      s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
      
      # prevent socket from being left in TIME_WAIT state, enabling reuse
      s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      s.bind((HOST, 0))

      # Include IP headers
      s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

      # receive all packages
      s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    self.s = s
  
  def __enter__(self):
    return self.s

  def __exit__(self, *args, **kwargs):
    if os.name == 'posix':
      import fcntl
      self.ifr.ifr_flags ^= FLAGS.IFF_PROMISC # mask it off (remove)
      fcntl.ioctl(self.s, FLAGS.SIOCSIFFLAGS, self.ifr) # update
    else:
      # disabled promiscuous mode
      self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def sniffer(ifcname, count, bufferSize=65565, showPort=False, showRawData=False):

    with PromiscuousSocketManager(ifcname) as s:
      for i in range(count):
  
          # receive a package
          (rawdata,ll) = s.recvfrom(bufferSize)
          print(ll)
          eth_frame = Ether(rawdata)
          # eth_frame.show()

