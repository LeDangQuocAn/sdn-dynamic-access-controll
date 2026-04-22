import json
import os
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

class AuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AuthController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

    def _load_ip_list(self, filename):
        file_path = os.path.join(self.base_dir, filename)
        with open(file_path, 'r') as f:
            data = json.load(f)
        ips = data.get('ips', [])
        return ips if isinstance(ips, list) else []

    def get_lists(self):
        # Đọc trực tiếp từ file mỗi lần gọi để lấy dữ liệu mới nhất (Dynamic)
        try:
            wl = self._load_ip_list('whitelist.json')
            try:
                bl = self._load_ip_list('blacklist.json')
            except FileNotFoundError:
                # Hỗ trợ tên file cũ để tránh vỡ demo khi chưa đổi tên file.
                bl = self._load_ip_list('backlist.json')
                self.logger.warning("Using legacy filename backlist.json. Please rename to blacklist.json.")
            return wl, bl
        except Exception as e:
            self.logger.error("Lỗi đọc file JSON: %s", e)
            return [], []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Rule mặc định: Gửi mọi gói tin lên Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # BẮT ĐẦU LOGIC AUTHENTICATE
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            wl, bl = self.get_lists()

            if src_ip in bl:
                self.logger.info("BLOCKED: %s nằm trong Blacklist!", src_ip)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                # Action rỗng = DROP
                self.add_flow(datapath, 100, match, []) 
                return

            if src_ip not in wl:
                # In ra log nhưng KHÔNG đẩy rule, để giữ trạng thái chờ xác thực
                self.logger.info("UNAUTHORIZED: %s chưa xác thực. Drop gói tin.", src_ip)
                return

            self.logger.info("AUTHORIZED: %s hợp lệ, cho phép đi qua.", src_ip)

        # L2 Forwarding bình thường cho ARP và các IP Whitelist
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Lưu rule lại để lần sau không cần hỏi Controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)