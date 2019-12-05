/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 0x06;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> index;
    bit<1>  syn_ok;
    bit<1>  rst_ok;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // Save state in these register.
    register<bit<1>>(65536) checking_hosts_syn;
    register<bit<1>>(65536) checked_hosts_rst;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action reg_syn_gen_synack() {
    	bit<48> tmp1=hdr.ethernet.dstAddr;
	bit<32> tmp2=hdr.ipv4.dstAddr;
	bit<16> tmp3=hdr.tcp.dstPort;
   
    	checking_hosts_syn.write(meta.index,1w1);
	
	// Swap src_mac,ip,port and dst_mac,ip,port
	// Change acknumber テスト佐藤あああ
	standard_metadata.egress_spec = standard_metadata.ingress_port;
	hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
	hdr.tcp.dstPort = hdr.tcp.srcPort;
	hdr.ethernet.dstAddr = tmp1;
	hdr.ipv4.dstAddr = tmp2;
	hdr.tcp.dstPort = tmp3;
	// Set acknumber to incorrect number
	hdr.tcp.ackNo = 32w0x0;
	hdr.tcp.syn = 1;
	hdr.tcp.ack = 1;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action reg_rst() {
        checking_hosts_syn.read(meta.syn_ok,meta.index);
    	if (meta.syn_ok==1){
    		checked_hosts_rst.write(meta.index,1);
	}
    }
    table auth {
        key = {
	    hdr.ipv4.dstAddr: lpm;
            hdr.tcp.syn : exact;
	    hdr.tcp.rst : exact;
	    meta.rst_ok : exact;
	    
        }
        actions = {
            ipv4_forward;
	    reg_syn_gen_synack;
	    reg_rst;
            drop;
            NoAction;
        }
	const entries ={
        (0x0a000102, 1, _ ,1) : ipv4_forward(0x001b21bb23c0,0x2);
	(0x0a000101, 1, _ ,1) : ipv4_forward(0xa0369fa0ecac,0x1);
	(_, 1 , 0 , 0) : reg_syn_gen_synack();
	(_, 0 , 1 , 0) : reg_rst();
	}
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
		hash(meta.index,HashAlgorithm.crc16,32w0,{hdr.ethernet.srcAddr, hdr.ipv4.srcAddr, hdr.tcp.srcPort},32w65536);
		// Check checked_hosts_rst
		checked_hosts_rst.read(meta.rst_ok,meta.index);
		auth.apply();
		exit;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	update_checksum(
	    hdr.tcp.isValid(),
            { hdr.tcp.srcPort,
	      hdr.tcp.dstPort,
              hdr.tcp.seqNo,
              hdr.tcp.ackNo,
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.ecn,
              hdr.tcp.urg,
              hdr.tcp.ack,
              hdr.tcp.psh,
              hdr.tcp.rst,
	      hdr.tcp.syn,
	      hdr.tcp.fin,
	      hdr.tcp.window,
	      hdr.tcp.urgetnPtr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
	    
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
