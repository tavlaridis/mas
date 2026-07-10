"""
Military Alert System (MAS) Ryu SDN Controller

Built on the UAdelaide SDN Template Scripts (base_ryu_template.py style).

What it does
------------
The controller drives the central **Alert Switch** (DPID 1) in fully reactive
mode (no routing flows are ever installed on it — FR5) and the four beacon
switches

Pipeline for one alert (FR1 / FR3):

    Alert Terminal --(coded IP:port)--> Alert Switch
        controller decodes  IP -> beacons,  port, terminal
        controller rewrites src=254.254.254.254 dst=253.253.253.253 dport=1
        controller forwards the rewritten packet over the AS to beacon link
    Beacon Switch --(254.254.254.254 -> 253.253.253.253:1)--> Terminal

Anything that is not recognisable MAS traffic is dropped and logged (FR2).
Everything that happens is printed as a live feed on this console (FR4).
"""

from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, ether_types


# Codes
# The Alert Switch is DPID 1. Each Beacon's DPID equals the Alert switch
# egress port that reaches it (b1 = DPID 2 on AS port 2 etc.)
# That 1:1 mapping is set up deliberately in the topology so the
# controller can use a single number for "which beacon"

ALERT_SWITCH_DPID = 1
BEACON_DPIDS = {2, 3, 4, 5}

# Coded destination IP to Alert-Switch egress port (== target beacon DPID)
IP_TO_BEACON_PORTS = {
    "192.168.1.1": [2],            # Beacon 1 (AS port 2)
    "172.16.1.1":  [3],            # Beacon 2 (AS port 3)
    "8.8.8.8":     [4],            # Beacon 3 (AS port 4)
    "1.1.1.1":     [5],            # Beacon 4 (AS port 5)
    "77.77.77.77": [2, 3, 4, 5],   # All beacons (broadcast)
}

# Coded destination port for Beacon egress port toward the terminals
PORT_TO_TERMINAL_PORTS = {
    20:   [2],          # Terminal 1 (Beacon port 2)
    22:   [3],          # Terminal 2 (Beacon port 3)
    3389: [4],          # Terminal 3 (Beacon port 4)
    7777: [2, 3, 4],    # All Terminals (broadcast)
}

# FR3 — uniform header values written on every packet leaving the Alert Switch
# Rewrite constants
REWRITE_SRC_IP = "254.254.254.254"
REWRITE_DST_IP = "253.253.253.253"
REWRITE_DST_PORT = 1

UDP_PROTO = 17

# AS port 2 - Beacon 1
def beacon_name(as_port):
    return "Beacon %d" % (as_port - 1)        
 
 # Beacon port 2  T1
def terminal_name(beacon_port):
    return "T%d" % (beacon_port - 1)          

class MilitaryAlertSystem(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MilitaryAlertSystem, self).__init__(*args, **kwargs)
        # Per-beacon first in first out of "terminal port lists" awaiting an obfuscated packet
        self.beacon_queue = defaultdict(deque)
        self.logger.info("\n  Military Alert System controller online — waiting for switches...\n")

    # flow helper from the template
    def install_flow(self, datapath, priority, match, actions=None,
                     table_id=0, idle_timeout=0, hard_timeout=0):
        actions = actions or []
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = []
        if actions:
            instructions.append(
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=instructions, table_id=table_id,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _packet_out(self, datapath, in_port, data, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # switch connect: install ONLY a table-miss flow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id

        # The table-miss flow sends every unmatched packet to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.install_flow(datapath, priority=0, match=match, actions=actions)

        if dpid == ALERT_SWITCH_DPID:
            role = "ALERT SWITCH (reactive, no routing flows)"
        elif dpid in BEACON_DPIDS:
            role = beacon_name(dpid) + " switch"
        else:
            role = "unknown switch"
        self.logger.info("[connect] DPID %s — %s", dpid, role)

    # main packet in dispatch
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        if dpid == ALERT_SWITCH_DPID:
            self._handle_alert_switch(datapath, in_port, msg.data, pkt)
        elif dpid in BEACON_DPIDS:
            self._handle_beacon(datapath, dpid, in_port, msg.data)
        # any other switch: ignore silently

    # Alert Switch: decode, drop, or rewrite and forward 
    def _handle_alert_switch(self, datapath, in_port, data, pkt):
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # FR2 — only IPv4/UDP can be a MAS alert
        if ip is None or ip.proto != UDP_PROTO or udp_pkt is None:
            etype = hex(eth.ethertype) if eth else "?"
            self._drop("ALERT SWITCH", "non-MAS traffic (ethertype=%s, not IPv4/UDP)" % etype)
            return

        dst_ip = ip.dst
        dst_port = udp_pkt.dst_port

        beacon_ports = IP_TO_BEACON_PORTS.get(dst_ip)
        terminal_ports = PORT_TO_TERMINAL_PORTS.get(dst_port)

        # FR2 — recognised codes only
        if beacon_ports is None or terminal_ports is None:
            self._drop("ALERT SWITCH",
                       "unrecognised code %s:%s (not part of MAS)" % (dst_ip, dst_port))
            return

        message = self._extract_message(pkt)
        beacons = ", ".join(beacon_name(p) for p in beacon_ports)
        terminals = ", ".join(terminal_name(p) for p in terminal_ports)

        # FR4 — live feed
        self.logger.info("=" * 64 )
        self.logger.info("[ALERT]"
                         " coded address %s%s:%s%s", dst_ip, dst_port)
        self.logger.info("   target beacons   : %s%s%s", beacons)
        self.logger.info("   target terminals : %s%s%s", terminals)
        self.logger.info("   message          : %s\"%s\"%s", message)
        self.logger.info("   %sobfuscate -> src=%s dst=%s dport=%s%s",
                         REWRITE_SRC_IP, REWRITE_DST_IP, REWRITE_DST_PORT)

        # FR3 — rewrite header fields, then output toward each target beacon.
        # One packet-out: set fields once, then emit on every target AS port.
        actions = [
            parser.OFPActionSetField(ipv4_src=REWRITE_SRC_IP),
            parser.OFPActionSetField(ipv4_dst=REWRITE_DST_IP),
            parser.OFPActionSetField(udp_dst=REWRITE_DST_PORT),
        ]
        for bp in beacon_ports:
            # remember which terminals the next obfuscated packet at this beacon is for
            self.beacon_queue[bp].append(list(terminal_ports))
            actions.append(parser.OFPActionOutput(bp))

        self.logger.info("   forwarding out AS ports %s", beacon_ports)
        self.logger.info("=" * 64 )
        self._packet_out(datapath, in_port, data, actions)

    # Beacon switch: deliver the obfuscated packet to terminals
    def _handle_beacon(self, datapath, dpid, in_port, data):
        parser = datapath.ofproto_parser

        if not self.beacon_queue[dpid]:
            # FR2 — nothing expected here: not MAS traffic
            self._drop(beacon_name(dpid), "unexpected traffic (no pending MAS delivery)")
            return

        terminal_ports = self.beacon_queue[dpid].popleft()
        actions = [parser.OFPActionOutput(p) for p in terminal_ports]
        names = ", ".join(terminal_name(p) for p in terminal_ports)

        self.logger.info("%s[%s]%s obfuscated packet -> delivering to %s%s%s (ports %s)",
                         beacon_name(dpid), names,
                         terminal_ports)
        self._packet_out(datapath, in_port, data, actions)

    # helpers
    def _drop(self, where, reason):
        # No output action == packet is dropped. Just log it (FR2 + FR4).
        self.logger.warning("%s[%s] DROP%s %s", where, reason)

    @staticmethod
    def _extract_message(pkt):
        last = pkt.protocols[-1] if pkt.protocols else None
        if isinstance(last, (bytes, bytearray)):
            return bytes(last).decode("utf-8", errors="replace").strip()
        return ""

    # surface OpenFlow errors (from the template)
    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error("%s[OpenFlow error]%s DPID %s type=%s code=%s",
                          ev.msg.datapath.id, msg.type, msg.code)
