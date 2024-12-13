from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp  # Make sure TCP is imported

class DoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DoSDetection, self).__init__(*args, **kwargs)
        self.packet_counts = {}
        self.threshold = 1000  # Set threshold for DoS detection

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)  # Check for TCP packets

        # Process only if it's an IP and TCP packet
        if ip_pkt and tcp_pkt:
            src_ip = ip_pkt.src
            self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1

            # Log packet count
            self.logger.info(f"TCP Packet from {src_ip}: count {self.packet_counts[src_ip]}")

            # Block source if count exceeds threshold
            if self.packet_counts[src_ip] > self.threshold:
                self.logger.info(f"Blocked DoS source: {src_ip}")
                match = parser.OFPMatch(ipv4_src=src_ip)
                actions = []
                self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
