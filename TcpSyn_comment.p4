/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// ether_typeやproto_typeはOpenFlowで要求されていなくても用意
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 0x06;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// ↓ヘッダはOpenFlowで要求されていないプロトコルでも用意
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

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}
//↑ヘッダはOpenFlowで要求されていないプロトコルでも用意

//
struct metadata {
    bit<32> index;
    bit<1>  syn_ok;
    bit<1>  rst_ok;
}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// ↓OpenFlowのプログラムに関係なく必要
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
	    //↓1.eth_type=0800なら必要
            TYPE_IPV4: parse_ipv4;
            //↑1.eth_type=0800なら必要
	    default: accept;
        }
    }
// ↑OpenFlowのプログラムに関係なく必要
//↓1.eth_type=0800なら必要
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	    //↓1.ip_proto=6なら必要
            TYPE_TCP: parse_tcp;
	    //↑1.ip_proto=6なら必要
            default: accept;
        }
    }
//↑1.eth_type=0800なら必要
//↓1.ip_proto=6なら必要
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}
//↑1.ip_proto=6なら必要

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//↓OpenFlowのプログラムに関係なく必要
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
//↑OpenFlowのプログラムに関係なく必要
    // Save state in these register.
    register<bit<1>>(65536) checking_hosts_syn;
    register<bit<1>>(65536) checked_hosts_rst;
    
    //↓OpenFlowのプログラムに関係なく必要
    action drop() {
        mark_to_drop(standard_metadata);
    }
    //↑OpenFlowのプログラムに関係なく必要
    //↓ 2.指定のIPを指定のPortに転送
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    //↑ 2.指定のIPを指定のPortに転送
    //↓ 4.SYNフラグだった時の処理（FlowMod,Packet_out）
    action reg_syn_gen_synack() {
    	bit<48> tmp1=hdr.ethernet.dstAddr;
	bit<32> tmp2=hdr.ipv4.dstAddr;
	bit<16> tmp3=hdr.tcp.dstPort;
   
    	checking_hosts_syn.write(meta.index,1w1);
	
	// Swap src_mac,ip,port and dst_mac,ip,port
	// Change acknumber
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
    //↑ 4.SYNフラグだった時の処理（FlowMod,Packet_out）
    //↓ 5.RSTフラグだった時の処理（FlowMod）
    action reg_rst() {
    	checked_hosts_rst.write(meta.index,1);
    }
    //↑ 5.RSTフラグだった時の処理（FlowMod)
    table ipv4_lpm {
        key = {
	    hdr.ipv4.dstAddr: lpm;
        }
	//↓ 2.指定のIPを指定のPortに転送
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
	//↑ 2.指定のIPを指定のPortに転送
	//↓ 2.指定のIPを指定のPortに転送
	const entries ={
        (0x0a000102) : ipv4_forward(0x001b21bb23c0,0x2);
	}
	//↑ 2.指定のIPを指定のPortに転送
	//↓OpenFlowのコードに関係なく必要
        default_action = drop();
	//↑OpenFlowのコードに関係なく必要
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            //↓1.TCPかどうかの処理部分
            if (hdr.tcp.isValid()) {
	        // ↓3.テーブルに存在するかどうか(FlowModで登録されるエントリ群)
		if (hdr.tcp.syn==1){
		    hash(meta.index,HashAlgorithm.crc16,32w0,{hdr.ethernet.dstAddr, hdr.ipv4.dstAddr, hdr.tcp.dstPort,
			hdr.ethernet.srcAddr, hdr.ipv4.srcAddr, hdr.tcp.srcPort},32w65536);
		    //checked_hosts_rstレジスタに登録したことがあるか
		    checked_hosts_rst.read(meta.rst_ok,meta.index);
                    if (meta.rst_ok==1){
                    	ipv4_lpm.apply();
                        exit;
                    } else {
		    	reg_syn_gen_synack();
			exit;
		    }
		} else if(hdr.tcp.rst==1){
                    hash(meta.index,HashAlgorithm.crc16,32w0,{hdr.ethernet.dstAddr, hdr.ipv4.dstAddr, hdr.tcp.dstPort,
	            	hdr.ethernet.srcAddr, hdr.ipv4.srcAddr, hdr.tcp.srcPort},32w65536);
                    //checking_hosts_synレジスタに登録したことがあるか
		    checking_hosts_syn.read(meta.syn_ok,meta.index);
                    if (meta.syn_ok==1){
                        reg_rst();
                        exit;
                    }
                }
            }
	    ipv4_lpm.apply();
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
//↓OpenFlowのコードに関係なく必要
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
//↓1.TCPかどうか
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
	      hdr.tcp.urgentPtr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
//↑1.TCPかどうか
    }
}
//↑OpenFlowのコードに関係なく必要
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
//↓OpenFlowのコードに関係なく必要
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	//↓1.TCPかどうか
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
	//↑1.TCPかどうか
    }
}
//↑OpenFlowのコードに関係なく必要
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
//↓OpenFlowのコードに関係なく必要
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
//↑OpenFlowのコードに関係なく必要
