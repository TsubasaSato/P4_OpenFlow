/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

/* This program is for ARP 
 * Original program is https://github.com/p4lang/p4c/blob/master/testdata/p4_16_bmv_errors/issue610-bmv2.p4#L104
*/

/*************************************************************************
 ***********************  C O N S T A N T S  *****************************
 *************************************************************************/
      /*  Define the useful global constants for your program */
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
        /*  Define the headers the program will recognize */

/*
 * Standard ethernet header
 */
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<9>   port_id_t;

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    ipv4_addr_t  srcAddr;
    ipv4_addr_t  dstAddr;
}

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    mac_addr_t  sha;
    ipv4_addr_t spa;
    mac_addr_t  tha;
    ipv4_addr_t tpa;
}

/* Assemble headers in a single struct */
struct my_headers_t {
    ethernet_t    ethernet;
    arp_t         arp;
    arp_ipv4_t    arp_ipv4;
    ipv4_t        ipv4;
}


/*************************************************************************
 ***********************  M E T A D A T A  *******************************
 *************************************************************************/
        /*  Define the global metadata for your program */

struct my_metadata_t {
    ipv4_addr_t dst_ipv4;
    mac_addr_t  mac_da;
    mac_addr_t  mac_sa;
    port_id_t   egress_port;
    mac_addr_t  my_mac;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
error {
    IPv4_InvalidHeader,
    IPv4_ChecksumError
}

parser MyParser(
    packet_in             packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    Checksum16() ipv4_checksum;
    bit<16>      ck;

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default        : accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4, error.IPv4_InvalidHeader);
        verify(hdr.ipv4.ihl < 5,      error.IPv4_InvalidHeader);
        ck = ipv4_checksum.get(
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
        verify(hdr.ipv4.hdrChecksum == ck, error.IPv4_ChecksumError);

        meta.dst_ipv4 = hdr.ipv4.dstAddr;
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(
    in    my_headers_t   hdr,
    inout my_metadata_t  meta)
{
    apply {   }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(
    inout my_headers_t     hdr,
    inout my_metadata_t    meta,
    inout standard_metadata_t  standard_metadata)
{
    action drop() {
        mark_to_drop();
        exit; // Exit from MyIngress block
    }

    action set_dst_info(mac_addr_t mac_da,
                        mac_addr_t mac_sa,
                        port_id_t  egress_port)
    {
        meta.mac_da      = mac_da;
        meta.mac_sa      = mac_sa;
        meta.egress_port = egress_port;
    }

    table ipv4_lpm {
        key     = { meta.dst_ipv4 : lpm; }
        actions = { set_dst_info; drop;  }
        default_action = drop();
    }

    action forward_ipv4() {
        hdr.ethernet.dstAddr = meta.mac_da;
        hdr.ethernet.srcAddr = meta.mac_sa;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;

        standard_metadata.egress_spec = meta.egress_port;
    }

    action send_arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = meta.mac_da;

        hdr.arp.oper         = ARP_OPER_REPLY;

        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = meta.mac_da;
        hdr.arp_ipv4.spa     = meta.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table forward {
        key = {
            hdr.arp.isValid()      : exact;
            hdr.arp.oper           : ternary;
            hdr.arp_ipv4.isValid() : exact;
            hdr.ipv4.isValid()     : exact;
        }
        actions = {
            forward_ipv4;
            send_arp_reply;
            drop;
        }
        const default_action = drop();
        const entries = {
            ( true, ARP_OPER_REQUEST, true, false ) : send_arp_reply();
            ( false, _,               false, true ) : forward_ipv4();
        }
    }

    apply {
        meta.my_mac = 0x000102030405;
        ipv4_lpm.apply();
        forward.apply();
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t standard_metadata) {
    apply {    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/
control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
{
    Checksum16() ipv4_checksum;

    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_checksum.get(
                {
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.totalLen,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
                });
        }
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        /* ARP Case */
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        /* IPv4 case */
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
