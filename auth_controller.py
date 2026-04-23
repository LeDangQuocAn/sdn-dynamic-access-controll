import json
import os
import time
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

    def _load_json_file(self, filename, default):
        file_path = os.path.join(self.base_dir, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            return default
        except Exception as e:
            self.logger.error("Lỗi đọc file %s: %s", filename, e)
            return default

        return data if isinstance(data, dict) else default

    def _load_ip_list(self, filename):
        data = self._load_json_file(filename, {})
        ips = data.get('ips', [])
        return ips if isinstance(ips, list) else []

    def _load_sessions(self):
        data = self._load_json_file('sessions.json', {})
        sessions = data.get('sessions', {})
        return sessions if isinstance(sessions, dict) else {}

    def _is_session_active(self, src_ip):
        sessions = self._load_sessions()
        expires_at = sessions.get(src_ip)
        if expires_at is None:
            return False

        try:
            expires_at = float(expires_at)
        except (TypeError, ValueError):
            return False

        return time.time() < expires_at

    def get_lists(self):
        # Đọc trực tiếp từ file mỗi lần gọi để lấy dữ liệu mới nhất (Dynamic)
        try:
            wl = self._load_ip_list('whitelist.json')
            bl = self._load_ip_list('blacklist.json')
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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None, idle_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_kwargs = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': inst,
        }

        if hard_timeout is not None:
            flow_kwargs['hard_timeout'] = hard_timeout

        if idle_timeout is not None:
            flow_kwargs['idle_timeout'] = idle_timeout

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            flow_kwargs['buffer_id'] = buffer_id

        mod = parser.OFPFlowMod(**flow_kwargs)
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
            session_active = self._is_session_active(src_ip)

            if src_ip in bl:
                self.logger.info("BLOCKED: %s nằm trong Blacklist!", src_ip)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                # Action rỗng = DROP
                self.add_flow(datapath, 100, match, [])
                return

            if src_ip in wl:
                self.logger.info("AUTHORIZED: %s hợp lệ theo whitelist tĩnh.", src_ip)
            elif session_active:
                self.logger.info("AUTHORIZED: %s còn trong phiên hợp lệ, cho phép đi qua.", src_ip)
            else:
                # In ra log nhưng KHÔNG đẩy rule, để giữ trạng thái chờ xác thực
                self.logger.info("UNAUTHORIZED: %s chưa xác thực. Drop gói tin.", src_ip)
                return

        # L2 Forwarding bình thường cho ARP và các IP Whitelist
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Lưu rule lại để lần sau không cần hỏi Controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            flow_hard_timeout = 60 if pkt_ipv4 and session_active else None
            self.add_flow(datapath, 1, match, actions, msg.buffer_id, hard_timeout=flow_hard_timeout)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)