from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


class TCPResponder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TCPResponder, self).__init__(*args, **kwargs)
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.ip_addr = '192.0.2.9'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_tcp)
            return

    def _handle_tcp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_tcp):
        pkt_in = packet.Packet()

        # Mac in received pkt
        pkt_in.add_protocol(
            ethernet.ethernet(
                dst=pkt_ethernet.src,
                src=pkt_ethernet.dst,
            ),
        ) 
        # IP in received pkt
        pkt_in.add_protocol(
            ipv4.ipv4(
                dst=pkt_ipv4.src,
                src=pkt_ipv4.dst,
                proto=in_proto.IPPROTO_TCP,
            ),
        )
        # Port , Seq , Ack and Flags in received pkt
        pkt_in.add_protocol(
            tcp.tcp(
                src_port=pkt_tcp.dst,
                dst_port=pkt_tcp.src,
            ),
         )
        payload_data = b'arbitrary'  # as a raw binary
        pkt_in.add_protocol(payload_data)
        self.send_packet(datapath,port,pkt_in)
        
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


"""TRASH CODE
print('*** constructed packet')
print(pkt_in)

print('*** binary of constructed packet')
print(binary_str(pkt_in.data))

print('*** parsed packet')
pkt_out = packet.Packet(pkt_in.data)
print(pkt_out)

print('*** get payload of TCP')
print(pkt_out.protocols[-1])
"""
