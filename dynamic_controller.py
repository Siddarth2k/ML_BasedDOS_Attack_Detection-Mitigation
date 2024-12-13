from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import time

class DoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DoSDetection, self).__init__(*args, **kwargs)
        self.packet_counts = {}  # Track packet counts per IP
        self.timestamps = {}  # Track last packet arrival time per IP
        self.blocked_ips = set()  # Track blocked IPs
        self.model = self.train_ml_model()  # Train the ML model

    def train_ml_model(self):
        """Train a simple Random Forest model."""
        np.random.seed(42)
        num_samples = 1000
        packet_counts = np.random.randint(1, 2000, size=(num_samples,))
        time_intervals = np.random.uniform(0.1, 10, size=(num_samples,))
        labels = (packet_counts < 1000).astype(int)  # 0: Malicious, 1: Legitimate

        features = np.column_stack((packet_counts, time_intervals))
        clf = RandomForestClassifier(n_estimators=10, random_state=42)
        clf.fit(features, labels)
        self.logger.info("Trained ML model on synthetic data.")
        return clf

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle PacketIn events."""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Process only if IP and TCP packets
        if ip_pkt and tcp_pkt:
            src_ip = ip_pkt.src
            self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
            packet_count = self.packet_counts[src_ip]

            # Calculate time interval
            time_interval = time.time() - self.timestamps.get(src_ip, time.time())
            self.timestamps[src_ip] = time.time()

            # ML model prediction
            features = np.array([[packet_count, time_interval]])
            prediction = self.model.predict(features)[0]

            # Log the prediction
            self.logger.info(f"TCP Packet from {src_ip}: count={packet_count}, prediction={prediction}")

            # Block malicious IPs 
            if prediction == 0:
                self.logger.info(f"Malicious packet blocked from Source {src_ip}")

                # If IP not already blocked, add a drop flow
                if src_ip not in self.blocked_ips:
                    self.logger.info(f"Malicious IP detected: {src_ip}, installing drop flow")
                    self.blocked_ips.add(src_ip)
                    match = parser.OFPMatch(ipv4_src=src_ip)
                    self.add_flow(datapath, 2, match, [])  # Priority 2, drop rule

    def add_flow(self, datapath, priority, match, actions):
        """Install a flow rule in the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=10,
            hard_timeout=30
        )
        self.logger.info(f"Installing flow: priority={priority}, match={match}, actions={actions}")
        datapath.send_msg(mod)
