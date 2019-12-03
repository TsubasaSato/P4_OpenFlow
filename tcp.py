from ryu.utils import binary_str
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

pkt_in = packet.Packet()

# 入ってきたパケットの取得方法を知る必要あり

# 入ってきたパケットのMacを入れる
pkt_in.add_protocol(
    ethernet.ethernet(
        dst='11:22:33:44:55:66',
        src='aa:bb:cc:dd:ee:ff',
    ),
)
# 入ってきたパケットのIPを入れる
pkt_in.add_protocol(
    ipv4.ipv4(
        dst='10.0.1.1',
        src='10.0.1.2',
        proto=in_proto.IPPROTO_TCP,
    ),
)
# 入ってきたパケットのTCP情報を入れる
pkt_in.add_protocol(
    tcp.tcp(
        src_port=50080,
        dst_port=80,
    ),
)
payload_data = b'arbitrary'  # as a raw binary
pkt_in.add_protocol(payload_data)
pkt_in.serialize()

print('*** constructed packet')
print(pkt_in)

print('*** binary of constructed packet')
print(binary_str(pkt_in.data))

print('*** parsed packet')
pkt_out = packet.Packet(pkt_in.data)
print(pkt_out)

print('*** get payload of TCP')
print(pkt_out.protocols[-1])
