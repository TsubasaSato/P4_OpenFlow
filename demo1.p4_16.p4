/* -*- mode: P4_16 -*- */
/*
Copyright 2017 Cisco Systems, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


/*
ほぼすべてのP4プログラムに標準の#includeが含まれています。
その（短い）コンテンツはここで見ることができます：https://github.com/p4lang/p4c/blob/master/p4include/core.p4
 */
#include <core.p4>


/* v1model.p4は1つのP4_16「アーキテクチャ」を定義します。
つまり、入力パイプラインと出力パイプラインがありますか、それとも1つだけですか。
解析はどこで行われ、ターゲットデバイスにはいくつのパーサーがありますか？
内容はこちらで確認できます：https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4 
PSA（Portable Switch Architecture）バージョン1.1と呼ばれる標準のP4_16アーキテクチャが2018年11月22日に公開されました
ここ：https://p4.org/specs/ PSAアーキテクチャ用に記述されたP4_16プログラムには、v1model.p4の代わりにファイルpsa.p4を含める必要があり、
その後のプログラムのいくつかの部分では、この例とは異なるexternオブジェクトおよび関数を使用しますプログラムが表示されます。
v1model.p4アーキテクチャでは、イングレスはこれらのもので構成され、P4でプログラムされています。
各P4プログラムは、これらのものを選択するときに名前を付けることができます。
この部分でこのプログラムで使用される名前は、括弧内に示されています：+パーサー（parserImpl）
+受信ヘッダーのチェックサムを検証するための特別な制御ブロック（verifyChecksum）
+入力マッチアクションパイプライン（ingressImpl）次にパケットレプリケーションがありますエンジンとパケットバッファー。
P4でプログラムできません。 Egressは、P4でプログラムされた次の要素で構成されます。+出力マッチアクションパイプライン（egressImpl）
+送信ヘッダーのチェックサムの計算を目的とした特殊な制御ブロック（updateChecksum）
+デパーサー（一部のネットワークチップでは書き換えとも呼ばれるdeparserImpl）
 */

#include <v1model.p4>


/* bit <48>は、ちょうど48ビット幅の符号なし整数です。
P4_16には、2の補数の符号付き整数のint <N>と、最大サイズがNビットの可変長ヘッダーフィールドのvarbit <N>もあります。 */

/* ヘッダータイプは、受信パケットで解析するか、送信パケットで送信するすべてのヘッダーに必要です。*/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* 「メタデータ」は、パケットに関する情報に使用される用語ですが、パケットコンテンツ自体の内部にはない場合があります。
ブリッジドメイン（BD）またはVRF（仮想ルーティングおよび転送）ID。
必要に応じて、パケットヘッダーフィールドのコピーを含めることもできます。
これは、パケット内のいくつかの可能な場所の1つから入力できる場合に役立ちます。 
非IPトンネルパケットの外部IPv4宛先アドレス、またはIPトンネルパケットの内部IPv4宛先アドレス。 
メタデータの構造体は、必要に応じていくつでも定義できます。 
転送機能のメタデータをグループ化できるが、無関係なメタデータから分離できるように、複数の構造体が必要な人もいます。 */

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}


/*v1model.p4およびpsa.p4アーキテクチャでは、関心のあるすべてのヘッダーのインスタンスを含む1つのタイプを定義する必要があります。
これは通常、パーサーコードが解析するヘッダーインスタンスごとに1つのメンバーを持つ構造体です。
また、プログラムで使用するすべてのメタデータフィールドを含む別のタイプを定義する必要があります。
通常、構造体型であり、ビットベクトルフィールド、ネストされた構造体、またはその他の任意の型を含むことができます。
これらの2つのタイプのインスタンスは、パラメーターとして、アーキテクチャーによって定義されたトップレベルコントロールに渡されます。
たとえば、入力パーサーは、ヘッダータイプを含むパラメーターを「出力」パラメーターとして受け取り、解析が完了すると入力ヘッダーを返しますが、
入力制御ブロックは、同じパラメーターを最初から「入力」方向に受け取りますパーサーによって入力されますが、
入力制御ブロックはパケット処理中にヘッダーの内容を変更できます。注：パケットの外部および内部IPv4ヘッダーを解析する場合、
定義するヘッダーを含む構造体には、ipv4_t型、おそらく「outer_ipv4」や「inner_ipv4」などのフィールド名を持つ2つのメンバーが
含まれている必要がありますが、名前は完全にあなた次第です。
同様に、以下の構造タイプ名「メタデータ」および「ヘッダー」には、任意の名前を付けることができます。 */

struct metadata_t {
    fwd_metadata_t fwd_metadata;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}


/* ここの入力パーサーは非常に単純です。 すべてのパケットは14バイトのイーサネットヘッダーで始まり、エーテルタイプが0x0800である場合、
IPv4オプションが存在する可能性があるかどうかを無視して、IPv4ヘッダーの20バイトの必須部分の解析に進みます。 */

parser parserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    /*
    表記<decimal number> w <something>は、<something>が定数の符号なし整数値を表すことを意味します。 
    <decimal number>は、その数値のビット単位の幅です。
    「0x」は、後に続くものが16進数であることを指定するCの方法から取得されます。 
    10進数（特別なプレフィックスなし）、2進数（プレフィックス0b）、または8進数（0o）を実行することもできますが、
    8進数はCの場合と同様に_not_指定されていることに注意してください。<decimal number> s <something> 「s」は、
    数値が2の補数の符号付き整数値であることを示します。 P4プログラムのほぼすべての整数定数について、
    '<number> w'の幅の指定を省略しても通常は完全に問題ありません。なぜなら、コンパイラはコンテキストから幅を推測するからです。
    以下の割り当てでは、 '16w'を省略すると、コンパイラは0x0800が16ビット幅であると推測します。
    これは、ビット<16>定数の値として割り当てられているためです。
     */
    const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

    /* パーサーは、有限状態マシンとして指定され、FSMの各状態の「状態」定義があります。
    開始状態である「start」という名前の状態が必要です。 「遷移」ステートメントは、次の状態がどうなるかを示します。
    解析が完了したことを示す特別な状態「accept」と「reject」があり、
    「accept」は解析中にエラーがないことを示し、「reject」は何らかの解析エラーを示します。 */
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        /* extract（）は、上記のcore.p4＃include'dで宣言されたパケット用に定義されたメソッドの名前です。 
        パーサーの実行モデルは、受信したパケットの先頭への「ポインター」で始まります。
        extract（）メソッドを呼び出すときはいつでも、引数ヘッダーのサイズをビットBで受け取り、
        次のBビットをパケットからそのヘッダーにコピーし（そのヘッダーを有効にし）、ポインターをBビットだけパケットに進めます。
        BMv2 simple_switchと呼ばれるビヘイビアモデルなどの一部のP4ターゲットは、ヘッダーとポインターを8ビットの倍数に制限します。*/
        packet.extract(hdr.ethernet);
        /* 「select」キーワードは、Cの「switch」ステートメントのような式を導入しますが、各ケースの式はパーサー内の状態名でなければなりません。
        これにより、多くの可能なイーサネットタイプまたはIPv4プロトコル値の処理が便利になります。*/
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/* このプログラムは、入力および出力のマッチアクション「パイプライン」を持つP4ターゲットアーキテクチャ用です（P4言語については、
ターゲットハードウェアにパイプラインが必要である必要はありませんが、「パイプライン」は 現在の最高性能のターゲットデバイスには1つあります）。
ここで指定された入力一致アクションパイプラインは非常に小さく、2つのテーブルが順番に適用され、それぞれに単純なアクションがあります。 */

control ingressImpl(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t stdmeta)
{
    /*
なぜ1つのプリミティブなアクションを実行するだけのアクションを作成する必要があるのですか？ 
つまり、テーブルを定義するときに可能なアクションの1つとして 'mark_to_drop'を使用しないのはなぜですか？
P4_16コンパイラでは、プリミティブアクションをテーブルのアクションとして直接使用できないためです。
「複合アクション」、つまり以下のような「アクション」キーワードで明示的に定義されたアクションを使用する必要があります。 
mark_to_dropはv1model.hで定義されたextern関数で、適切な「標準メタデータ」フィールドにパケットをドロップする必要があることを示す
コードを設定することにより、動作モデルに実装されます。
オープンソースの動作モデルBMv2ソフトウェアスイッチに実装されている、
mark_to_dropの動作およびv1modelアーキテクチャのその他の操作に関する詳細なドキュメントに興味がある場合は、次のページを参照してください。
https：//github.com/p4lang/behavioral -model / blob / master / docs / simple_switch.md
     */
    action my_drop() {
        mark_to_drop(stdmeta);
    }

    /* アクションset_l2ptrのl2ptrパラメーターに「in」、「out」、または「inout」の方向が指定されていないことに注意してください。
    アクションのこのような方向のないパラメーターは、l2ptrの値がコントロールプレーンからのものであることを示します。
    つまり、テーブルipv4_da_lpmに1つ以上のテーブルエントリを作成するのはコントロールプレーンの責任です。
    追加されるそのようなエントリごとに、コントロールプレーンは以下を指定します。+検索キー。テーブルipv4_da_lpmの場合、
    これはhdr.ipv4.dstAddrフィールドの0〜32ビット長のプレフィックスです。 + P4プログラムで許可されているアクションの1つ。
    この場合、set_l2ptrまたはmy_drop（下の表に指定されている「アクション」リストから）。 +そのアクションのすべての無方向パラメータの値。
    コントロールプレーンがテーブルエントリにmy_dropアクションを選択する場合、アクションパラメーターはまったくないため、
    コントロールプレーンで何も指定する必要はありません。コントロールプレーンがテーブルエントリに対してset_l2ptrアクションを選択する場合、
    「l2ptr」パラメーターに32ビット値を指定する必要があります。この値は、そのエントリのターゲットのipv4_da_lpmテーブル結果に保存されます。
    パケットがP4プログラムによって処理され、ip4_da_lpmテーブルを検索し、その結果としてエントリとset_l2ptrアクションを照合するたびに、
    コントロールプレーンによって選択されたl2ptrの値は、set_l2ptrアクションのl2ptrパラメータの値になりますパケット転送時に実行されるため。 */
    action set_l2ptr(bit<32> l2ptr) {
        /* Nothing complicated here in the action.  The l2ptr value
         * specified by the control plane and stored in the table
         * entry is copied into a field of the packet's metadata.  It
         * will be used as the search key for the 'mac_da' table
         * below. */
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    table ipv4_da_lpm {
        key = {
            /* lpm means 'Longest Prefix Match'.  It is called a
             * 'match_kind' in P4_16, and the two most common other
             * choices seen in P4 programs are 'exact' and
             * 'ternary'. */
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_l2ptr;
            my_drop;
        }
        /* If at packet forwarding time, there is no matching entry
         * found in the table, the action specified by the
         * 'default_action' keyword will be performed on the packet.
         *
         * In this case, my_drop is only the default action for this
         * table when the P4 program is first loaded into the device.
         * The control plane can choose to change that default action,
         * via an appropriate API call, to a different action.  If you
         * put 'const' before 'default_action', then it means that
         * this default action cannot be changed by the control
         * plane. */
        default_action = my_drop;
    }

    /* This second table is no more complicated than the first.  The
     * search key in this case is 'exact', so no longest prefix match
     * going on here.  It would probably be implemented in the target
     * as a hash table.
     *
     * If the control plane adds an entry to this table and chooses
     * for that entry the action set_bd_dmac_intf, it must specify
     * values for all 3 of the directionless parameters bd, dmac, and
     * intf. */
    action set_bd_dmac_intf(bit<24> bd, bit<48> dmac, bit<9> intf) {
        meta.fwd_metadata.out_bd = bd;
        hdr.ethernet.dstAddr = dmac;
        stdmeta.egress_spec = intf;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table mac_da {
        key = {
            meta.fwd_metadata.l2ptr: exact;
        }
        actions = {
            set_bd_dmac_intf;
            my_drop;
        }
        default_action = my_drop;
    }

    /* Every control block must contain an 'apply' block.  The
     * contents of the apply block specify the sequential flow of
     * control of packet processing, including applying the tables you
     * wish, in the order you wish.
     *
     * This one is particularly simple -- always apply the ipv4_da_lpm
     * table, and regardless of the result, always apply the mac_da
     * table.  It is definitely possible to have 'if' statements in
     * apply blocks that handle many possible cases differently from
     * each other, based upon the values of packet header fields or
     * metadata fields. */
    apply {
        ipv4_da_lpm.apply();
        mac_da.apply();
    }
}

/* The egress match-action pipeline is even simpler than the one for
 * ingress -- just one table that can overwrite the packet's source
 * MAC address depending on its out_bd metadata field value. */
control egressImpl(inout headers_t hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t stdmeta)
{
    action my_drop() {
        mark_to_drop(stdmeta);
    }
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    table send_frame {
        key = {
            meta.fwd_metadata.out_bd: exact;
        }
        actions = {
            rewrite_mac;
            my_drop;
        }
        default_action = my_drop;
    }

    apply {
        send_frame.apply();
    }
}

/* The deparser controls what headers are created for the outgoing
 * packet. */
control deparserImpl(packet_out packet,
                     in headers_t hdr)
{
    apply {
        /* The emit() method takes a header.  If that header's hidden
         * 'valid' bit is true, then emit() appends the contents of
         * the header (which may have been modified in the ingress or
         * egress pipelines above) into the outgoing packet.
         *
         * If that header's hidden 'valid' bit is false, emit() does
         * nothing. */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);

        /* This ends the deparser definition.
         *
         * Note that for each packet, the target device records where
         * parsing ended, and it considers every byte of data in the
         * packet after the last parsed header as 'payload'.  For
         * _this_ P4 program, even a TCP header immediately following
         * the IPv4 header is considered part of the payload.  For a
         * different P4 program that parsed the TCP header, the TCP
         * header would not be considered part of the payload.
         * 
         * Whatever is considered as payload for this particular P4
         * program for this packet, that payload is appended after the
         * end of whatever sequence of bytes that the deparser
         * creates. */
    }
}

/* In the v1model.p4 architecture this program is written for, there
 * is a 'slot' for a control block that performs checksums on the
 * already-parsed packet, and can modify metadata fields with the
 * results of those checks, e.g. to set error flags, increment error
 * counts, drop the packet, etc. */
control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        /* The verify_checksum() extern function is declared in
         * v1model.p4.  Its behavior is implementated in the target,
         * e.g. the BMv2 software switch.
         *
         * It can takes a single header field by itself as the second
         * parameter, but more commonly you want to use a list of
         * header fields inside curly braces { }.  They are
         * concatenated together and the checksum calculation is
         * performed over all of them.
         *
         * The computed checksum is compared against the received
         * checksum in the field hdr.ipv4.hdrChecksum, given as the
         * 3rd argument.
         *
         * The verify_checksum() primitive can perform multiple kinds
         * of hash or checksum calculations.  The 4th argument
         * specifies that we want 'HashAlgorithm.csum16', which is the
         * Internet checksum.
         *
         * The first argument is a Boolean true/false value.  The
         * entire verify_checksum() call does nothing if that value is
         * false.  In this case it is true only when the parsed packet
         * had an IPv4 header, which is true exactly when
         * hdr.ipv4.isValid() is true, and if that IPv4 header has a
         * header length 'ihl' of 5 32-bit words.
         *
         * In September 2018, the simple_switch process in the
         * p4lang/behavioral-model Github repository was enhanced so
         * that it initializes the value of stdmeta.checksum_error to
         * 0 for all received packets, and if any call to
         * verify_checksum() with a first parameter of true finds an
         * incorrect checksum value, it assigns 1 to the
         * checksum_error field.  This field can be read in your
         * ingress control block code, e.g. using it in an 'if'
         * condition to choose to drop the packet.  This example
         * program does not demonstrate that.
         */
        verify_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
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
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

/* Also in the v1model.p4 architecture, there is a slot for a control
 * block that comes after the egress match-action pipeline, before the
 * deparser, that can be used to calculate checksums for the outgoing
 * packet. */
control updateChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        /* update_checksum() is declared in v1model.p4, and its
         * arguments are similar to verify_checksum() above.  The
         * primary difference is that after calculating the checksum,
         * it modifies the value of the field given as the 3rd
         * parameter to be equal to the newly computed checksum. */
        update_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
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
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}


/* This is a "package instantiation".  There must be at least one
 * named "main" in any complete P4_16 program.  It is what specifies
 * which pieces to plug into which "slot" in the target
 * architecture. */

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
