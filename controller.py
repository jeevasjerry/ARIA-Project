from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp


class ARIAController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARIAController, self).__init__(*args, **kwargs)

        # MAC learning table
        self.mac_to_port = {}

        # ARIA configuration
        self.SSH_PORT = 22

        # Current OVS topology:
        # 1 = h1
        # 2 = h2
        # 3 = aria-s1 -> Ubuntu host
        self.REDIRECT_PORT = 3

        # Cowrie information
        self.COWRIE_IP = "172.17.0.2"
        self.COWRIE_PORT = 2222

        self.logger.info("=" * 60)
        self.logger.info("             ARIA SDN CONTROLLER")
        self.logger.info("=" * 60)
        self.logger.info("SSH Detection      : ENABLED")
        self.logger.info("SSH Port           : 22")
        self.logger.info("Redirect Port      : 3")
        self.logger.info("Cowrie             : 172.17.0.2:2222")
        self.logger.info("=" * 60)

    # ==========================================================
    # SWITCH CONNECTION
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # ------------------------------------------------------
        # TABLE MISS
        # Send unknown packets to controller
        # ------------------------------------------------------

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            0,
            match,
            actions
        )

        # ------------------------------------------------------
        # SSH DETECTION FLOW
        #
        # TCP packets whose destination port is 22
        # are sent to the controller.
        # ------------------------------------------------------

        ssh_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_dst=22
        )

        ssh_actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            100,
            ssh_match,
            ssh_actions
        )

        # ------------------------------------------------------
        # LOG
        # ------------------------------------------------------

        self.logger.info("=" * 60)
        self.logger.info("Switch Connected Successfully!")
        self.logger.info(
            "Datapath ID : %016x",
            dpid
        )
        self.logger.info("SSH Detection Flow Installed")
        self.logger.info(
            "SSH Redirect Port : %s",
            self.REDIRECT_PORT
        )
        self.logger.info("=" * 60)

    # ==========================================================
    # ADD FLOW
    # ==========================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(mod)

    # ==========================================================
    # PACKET IN HANDLER
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        # ------------------------------------------------------
        # Parse packet
        # ------------------------------------------------------

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth is None:
            return

        src = eth.src
        dst = eth.dst

        dpid = datapath.id

        # ------------------------------------------------------
        # Extract IPv4 and TCP
        # ------------------------------------------------------

        ip_pkt = pkt.get_protocol(
            ipv4.ipv4
        )

        tcp_pkt = pkt.get_protocol(
            tcp.tcp
        )

        # ======================================================
        # SSH DETECTION
        # ======================================================

        if ip_pkt and tcp_pkt:

            if tcp_pkt.dst_port == self.SSH_PORT:

                # ------------------------------------------------
                # LOG ATTACK
                # ------------------------------------------------

                self.logger.info("=" * 60)
                self.logger.info("          SSH ATTACK DETECTED")
                self.logger.info("=" * 60)

                self.logger.info(
                    "Source IP       : %s",
                    ip_pkt.src
                )

                self.logger.info(
                    "Source Port     : %s",
                    tcp_pkt.src_port
                )

                self.logger.info(
                    "Original Target  : %s",
                    ip_pkt.dst
                )

                self.logger.info(
                    "Original Port    : %s",
                    tcp_pkt.dst_port
                )

                self.logger.info(
                    "Switch           : %s",
                    dpid
                )

                self.logger.info(
                    "Ingress Port     : %s",
                    in_port
                )

                self.logger.info(
                    "Redirect Port    : %s",
                    self.REDIRECT_PORT
                )

                self.logger.info(
                    "Cowrie Target    : %s:%s",
                    self.COWRIE_IP,
                    self.COWRIE_PORT
                )

                self.logger.info("=" * 60)

                # ------------------------------------------------
                # REDIRECT SSH PACKET
                #
                # Send the packet to the Ubuntu host through
                # aria-s1.
                # ------------------------------------------------

                redirect_actions = [
    parser.OFPActionSetField(
        eth_dst="12:a6:0b:c3:6b:9a"
    ),
    parser.OFPActionOutput(
        self.REDIRECT_PORT
    )
]

                redirect_packet = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=redirect_actions,
                    data=msg.data
                )

                datapath.send_msg(
                    redirect_packet
                )

                self.logger.info(
                    "[REDIRECT] SSH packet sent to Ubuntu host"
                )

                # ------------------------------------------------
                # IMPORTANT:
                # Do not continue with normal MAC forwarding.
                # ------------------------------------------------

                return

        # ======================================================
        # NORMAL MAC LEARNING
        # ======================================================

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port

        # ------------------------------------------------------
        # Find destination
        # ------------------------------------------------------

        if dst in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst]

        else:

            out_port = ofproto.OFPP_FLOOD

        # ------------------------------------------------------
        # Normal forwarding action
        # ------------------------------------------------------

        actions = [
            parser.OFPActionOutput(
                out_port
            )
        ]

        # ------------------------------------------------------
        # Install forwarding flow
        # ------------------------------------------------------

        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst
            )

            self.add_flow(
                datapath,
                1,
                match,
                actions
            )

        # ======================================================
        # SEND NORMAL PACKET
        # ======================================================

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:

            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

        self.logger.info(
            "Packet: %s -> %s | Port: %s",
            src,
            dst,
            out_port
        )
