# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Original file is simple_switch_13.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

# Connect from SERVER1

class TCPSYN13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(TCPSYN13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #Send packet to CONTROLLER
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #TableID:0 INGRESS_FILTERING
        match_t1 = parser.OFPMatch(eth_type=0x0800, 
                                     ip_proto=6)
        inst = [parser.OFPInstructionGotoTable(1)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=0, priority=2,
                                match=match_t1, instructions=inst))
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(4)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=0, priority=1,
                                match=match, instructions=inst))
   
        #TableID:1 CHECKED_TCP
        inst = [parser.OFPInstructionGotoTable(2)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=1, priority=1,
                                match=match, instructions=inst))
        
        #TableID:2 CHECKING_TCP
        inst = [parser.OFPInstructionGotoTable(3)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=2, priority=1,
                                match=match, instructions=inst))
       
        #TableID:3 UNCHECK_TCP
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=3, priority=1,
                                match=match, instructions=inst))
     
        #TableID:4 FORWARDING 2 => 1
        actions = [parser.OFPActionOutput(port=1)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=4, priority=1,
                                match=match, instructions=inst))

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        self.logger.info("packet-in %s" % (pkt,))
        # イーサネットを持つかどうか
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        # IPプロトコルを持つかどうか
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        # TCPプロトコルを持つかどうか
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            # TCPコントロールフラグのSYNフラグが立っているか
            if pkt_tcp.has_flags(tcp.TCP_SYN):
                # 不正なSYN/ACKパケットの生成
                pkt_in = packet.Packet()
                pkt_in.add_protocol(ethernet.ethernet(dst=pkt_ethernet.src, src=pkt_ethernet.dst)) 
                pkt_in.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=pkt_ipv4.dst,proto=inet.IPPROTO_TCP))
                pkt_in.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port,dst_port=pkt_tcp.src_port,bits=(tcp.TCP_SYN | tcp.TCP_ACK),ack=0,seq=500))
                # PacketOut
                out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
                datapath.send_msg(out)
                self._send_packet(datapath,port,pkt_in)
                
                
                # 認証中ホストとしてテーブルに記録
                # Flowmod(パケットの送信元Eth,IP,Port,送信先Eth,IP,PortをMatchとして、OpenFlowスイッチのテーブルにエントリ追加)
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                        eth_dst=pkt_ethernet.dst,eth_src=pkt_ethernet.src,
                                        ipv4_dst=pkt_ipv4.dst,ipv4_src=pkt_ipv4.src,
                                        tcp_dst=pkt_tcp.dst_port,tcp_src=pkt_tcp.src_port)
                datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=2, priority=10,
                                match=match, instructions=inst))

            # TCPコントロールフラグのRSTフラグが立っているか
            elif pkt_tcp.has_flags(tcp.TCP_RST):
                # 認証済みホストとしてテーブルに記録
                # Flowmod(パケットの送信元Eth,IP,Port,送信先Eth,IP,PortをMatchとして、OpenFlowスイッチのテーブルにエントリ追加)
                actions = [parser.OFPActionOutput(port=1)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                        eth_dst=pkt_ethernet.dst,eth_src=pkt_ethernet.src,
                                        ipv4_dst=pkt_ipv4.dst,ipv4_src=pkt_ipv4.src,
                                        tcp_dst=pkt_tcp.dst_port,tcp_src=pkt_tcp.src_port)
                datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=1, priority=10,
                                match=match, instructions=inst))
        else:
            return
