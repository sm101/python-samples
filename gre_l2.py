#!/usr/bin/python2
#
# This is L2 GRE encapsulation/decapsulation application. 
# o Application is L2 bridge between pair of specified interfaces. 
# o Source adddress for GRE packet does not need to be assigned to host
# o Encapsulation/decapsulation is driven by 'tunnels' and 'routes' global variables.
# o Ethernet header is preserved (no MAC address changes), even if enc/decap is performed
#   on a packet (no IP routing takse place)
#
# Example, how to run on lblackbird1.dev.plx as bridge/gre tunnel
# between p6p2 and p5p1:
#    python gre_l2.py  p6p2 p5p1
#
# Multi thread setup, exit and bridge code derived from https://gist.github.com/mgalgs/1856631.
#
#
import sys
import signal
from threading import Thread,Lock
from scapy.all import *

def usage():
    print 'Usage: gre_l2.py interface1 interface2'
    print ''

# Tunnel definitions
tunnels = {
  "gre0": {
        "local_address" : "10.0.1.102",
        "remote_address" : "10.0.1.104"
    }
}

# Routes to gre tunnels. For simplicity just /32 routes are supported.
routes = {
    "11.0.1.104" : "gre0"
}

# Packets emitted by us will be observed by the sniffer. They must not be considered
# in process_packet.
emitted = {}

# This class provides process_pkt method to GRE encapusulate/decapsulate
# packets while bridging traffic between input and output interfaces.
class GRE_L2():
    pktcnt = 0

    def __init__(self, tunnels, routes, eth_in, eth_out, name):
        self.tunnels = tunnels
        self.local_addresses = map(lambda (name,endpoints): endpoints["local_address"],
            tunnels.iteritems())
        self.routes = routes
        self.eth_in = eth_in
        self.eth_out = eth_out
        self.name = name

    def process_packet(self, pkt):
        self.pktcnt += 1
        p = pkt.copy()
        # Do not consider packets TXed by us (not completely correct test
        # since it is based on packet content and furthermore uses summary only
        # for comparison)
        if str(p) in emitted:
            del emitted[str(p)]
            return
        print "Considering: "
        print p.summary()
        try:
            if (IP in p) and (p[IP].dst in routes):
               print "Encapusulating ..."
               tunnel_name = self.routes[p[IP].dst]
               endpoints = self.tunnels[tunnel_name]
               p = encap((endpoints["local_address"],endpoints["remote_address"]), p)
            elif (GRE in p) and (p[IP].dst in self.local_addresses):
               print "Decapsulating ..."
               p = decap(p)
            sendp(p, iface=self.eth_out)
        except socket.error as e:
            # tolerate errno.EMSGSIZE
            if e.errno == EMSGSIZE:
                print "Would need to fragment packet:"
                print p.summary()
            else:
                raise e
        else:
            emitted[str(p)] = 1
        return ""

    def stopper_check(self, pkt):
        return not still_running_lock.locked()

    def sniffloop(self):
        sniff(iface=self.eth_in, prn=self.process_packet, stop_filter=self.stopper_check)

def encap(endpoints, p):
    """ Encapsulate in GRE.

    Args:
       endpoints (tuple): Local and remote tunnnel addresses, 
           for example ("10.0.1.102", "10.0.1.104")

       p: Scapy packet

    Returns:
       GRE packet with original datagram as payload.
    """
    
    eth_in = p[Ether]
    eth_l = Ether(src=eth_in.src, dst=eth_in.dst)
    ip_l = p[IP]
    gre = eth_l/IP(src=endpoints[0], dst=endpoints[1])/GRE()/ip_l
    return gre

def decap(p):
    """ Retrieve GRE packet's payload.

    Args:
       p (Scapy Packet): GRE packet

    Returns:
       GRE packet payload (original datagram).
    """
    eth_in = p[Ether]
    eth_l = Ether(src=eth_in.src, dst=eth_in.dst)
    inner_ip = p[GRE][IP]
    ip_pack = eth_l/inner_ip
    return ip_pack
        
# global list of running threads
threads = []
# global lock to signal that we're still running
still_running_lock = Lock()

def signal_handler(signal, frame):
    print 'Cleaning up sniff threads...'
    still_running_lock.release()
    try:
        for t in threads: t.join()
    except:
        pass
    print 'exiting.'
    sys.exit(0)

if __name__ == '__main__':
    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) != 3:
        usage()
        sys.exit(-1)

    (eth1, eth2) = sys.argv[1:]

    bridge1 = GRE_L2(tunnels, routes, eth1, eth2, 'A')
    bridge2 = GRE_L2(tunnels, routes, eth2, eth1, 'B')

    threads.append(Thread(target=bridge1.sniffloop))
    threads.append(Thread(target=bridge2.sniffloop))

    # set our "state" to running by acquiring the lock
    still_running_lock.acquire()

    for t in threads: t.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
