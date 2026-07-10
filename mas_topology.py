"""
Military Alert System (MAS) Mininet Topology

Built on the UAdelaide SDN Template Scripts (mininet_topology_builder.py style)

"""

import sys
import os

from mininet_helpers import createInitialNetwork, safeMininetStartupAndExit

"""
Fake default gateway for the Alert Terminal. It does not exist in the
topology, so we hand the terminal a static ARP entry for it at startup,
otherwise the kernel drops off the subnet UDP before it ever
reaches the alert switch
"""

GATEWAY_IP = "10.0.0.254"
GATEWAY_MAC = "00:00:00:00:00:fe"


def militaryAlertSystem():
    net = createInitialNetwork()

    # Central sdn-controlled alert switch
    alert_sw = net.addSwitch("as", dpid="1")

    # Alert terminal, the only sender. Non subnet codes route via the gateway
    at = net.addHost("at", ip="10.0.0.1/24", defaultRoute="via %s" % GATEWAY_IP)
    
    # Alert switch port 1 = Alert terminal
    net.addLink(at, alert_sw, port2=1)            

    # Four beacons, DPID == the alert switch port that reaches the beacon
    for b in range(1, 5):
        dpid = b + 1                              
        beacon = net.addSwitch("b%d" % b, dpid=str(dpid))
        net.addLink(alert_sw, beacon, port1=dpid, port2=1)   

        # Three terminals per beacon 
        for t in range(1, 4):
            term = net.addHost("b%dt%d" % (b, t))
            net.addLink(beacon, term, port1=t + 1)           

    net.start()

    # Static ARP for the nonexistent gateway so the terminal can resolve it
    at.cmd("arp -s %s %s" % (GATEWAY_IP, GATEWAY_MAC))

    print("\n[MAS] Topology up. Example commands:")
    print('  at:    echo "INCOMING" | nc -u -w0 192.168.1.1 22   # Beacon 1, Terminal 2')
    print('  at:    echo "ALL CLEAR" | nc -u -w0 77.77.77.77 7777 # every terminal, every beacon')
    print("  bXtY:  tcpdump udp port 1 -A                        # listen for alerts\n")

    safeMininetStartupAndExit(net)

topos = {
    "mas": (lambda: militaryAlertSystem()),
}

if __name__ == "__main__":
    militaryAlertSystem()
