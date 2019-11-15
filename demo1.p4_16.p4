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
        /* ここでのアクションは複雑ではありません。 コントロールプレーンによって指定され、テーブルエントリに保存されているl2ptr値は、
        パケットのメタデータのフィールドにコピーされます。 以下の「mac_da」テーブルの検索キーとして使用されます。*/
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    table ipv4_da_lpm {
        key = {
            /* lpmは「最長プレフィックス一致」を意味します。 
            P4_16では「match_kind」と呼ばれ、P4プログラムで見られる他の2つの最も一般的な選択肢は「exact」と「ternary」です。*/
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_l2ptr;
            my_drop;
        }
        /* パケットの転送時に、テーブルに一致するエントリが見つからない場合、「default_action」キーワードで指定されたアクションがパケットで実行されます。
        この場合、my_dropは、P4プログラムが最初にデバイスにロードされたときのこのテーブルのデフォルトアクションのみです。 
        コントロールプレーンは、適切なAPI呼び出しを介して、そのデフォルトアクションを別のアクションに変更することを選択できます。 
        'default_action'の前に 'const'を置くと、このデフォルトアクションはコントロールプレーンによって変更できないことを意味します。*/
        default_action = my_drop;
    }

    /* この2番目のテーブルは、最初のテーブルほど複雑ではありません。 この場合の検索キーは「完全一致」であるため、
    ここでは最長のプレフィックス一致は発生しません。 おそらく、ターゲットにハッシュテーブルとして実装されます。 
    ントロールプレーンがこのテーブルにエントリを追加し、
    そのエントリに対してアクションset_bd_dmac_intfを選択する場合、方向なしパラメーターbd、dmac、およびintfの3つすべての値を指定する必要があります。 */
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

    /* すべての制御ブロックには、「適用」ブロックが含まれている必要があります。 適用ブロックの内容は、希望する順序での希望するテーブルの適用を含む、
    パケット処理の制御のシーケンシャルフローを指定します。 これは特に単純です。常にipv4_da_lpmテーブルを適用し、結果に関係なく、
    常にmac_daテーブルを適用します。 パケットヘッダーフィールドまたはメタデータフィールドの値に基づいて、
    多くの可能性のあるケースを互いに異なる方法で処理する適用ブロックに「if」ステートメントを含めることは間違いなく可能です。 */
    apply {
        ipv4_da_lpm.apply();
        mac_da.apply();
    }
}

/*出力の一致アクションパイプラインは、入力のパイプラインよりもさらにシンプルです。
out_bdメタデータフィールドの値に応じて、パケットの送信元MACアドレスを上書きできるテーブルは1つだけです。 */
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

/* デパーサーは、発信パケット用に作成されるヘッダーを制御します。 */
control deparserImpl(packet_out packet,
                     in headers_t hdr)
{
    apply {
        /* emit（）メソッドはヘッダーを受け取ります。 そのヘッダーの隠された「有効な」ビットがtrueの場合、
        emit（）はヘッダーの内容（上記の入力または出力パイプラインで変更されている可能性があります）を送信パケットに追加します。 
        そのヘッダーの隠された「有効な」ビットがfalseの場合、emit（）は何もしません。 */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);

        /* これにより、デパーサー定義が終了します。 各パケットについて、ターゲットデバイスは解析の終了位置を記録し、
        最後に解析されたヘッダーの後のパケット内のデータのすべてのバイトを「ペイロード」と見なします。 
        _this_ P4プログラムの場合、IPv4ヘッダーの直後のTCPヘッダーもペイロードの一部と見なされます。
        TCPヘッダーを解析した別のP4プログラムの場合、TCPヘッダーはペイロードの一部と見なされません。
        このパケットのこの特定のP4プログラムのペイロードと見なされるものは何でも、
        そのペイロードは、デパーサーが作成するバイトシーケンスの終わりの後に追加されます。 */
    }
}

/*このプログラムが記述されているv1model.p4アーキテクチャには、既に解析されたパケットのチェックサムを実行する制御ブロックの「スロット」があり、
これらのチェックの結果でメタデータフィールドを変更できます。 
エラーフラグの設定、エラーカウントのインクリメント、パケットのドロップなど。*/
control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        /* verify_checksum（）extern関数はv1model.p4で宣言されています。その動作は、ターゲットに実装されています。
        BMv2ソフトウェアスイッチ。 2番目のパラメーターとして単一のヘッダーフィールドを単独で使用できますが、より一般的には、
        中括弧{}内のヘッダーフィールドのリストを使用します。それらは一緒に連結され、それらすべてに対してチェックサム計算が実行されます。
        計算されたチェックサムは、3番目の引数として指定されたフィールドhdr.ipv4.hdrChecksumで受信したチェックサムと比較されます。
        verify_checksum（）プリミティブは、複数の種類のハッシュまたはチェックサムの計算を実行できます。 4番目の引数は
        、インターネットチェックサムである 'HashAlgorithm.csum16'が必要であることを指定します。最初の引数はブール値のtrue / false値です。
        その値がfalseの場合、verify_checksum（）呼び出し全体は何もしません。この場合、解析されたパケットにIPv4ヘッダーがあり、
        hdr.ipv4.isValid（）がtrueであり、IPv4ヘッダーのヘッダー長が「ihl」の5 32ビットワードである場合にのみtrueになります。 
        2018年9月、p4lang / behavioral-model Githubリポジトリのsimple_switchプロセスが拡張され、
        すべての受信パケットのstdmeta.checksum_errorの値が0に初期化され、trueの最初のパラメーターでverify_checksum（）の呼び出しが見つかった場合
        不正なチェックサム値の場合、checksum_errorフィールドに1を割り当てます。このフィールドは、入力制御ブロックコードで読み取ることができます。 
        「if」条件で使用して、パケットのドロップを選択します。このサンプルプログラムはそれを示していません。
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

/* また、v1model.p4アーキテクチャには、出力マッチアクションパイプラインの後、
デパーサーの前に来る制御ブロック用のスロットがあり、発信パケットのチェックサムの計算に使用できます。 */
control updateChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        /* update_checksum（）はv1model.p4で宣言され、その引数は上記のverify_checksum（）に似ています。 
        主な違いは、チェックサムを計算した後、
        3番目のパラメーターとして指定されたフィールドの値を、新しく計算されたチェックサムと等しくなるように変更することです。 */
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


/*これは「パッケージのインスタンス化」です。 完全なP4_16プログラムには、少なくとも1つの名前の「メイン」が必要です。 
ターゲットアーキテクチャのどの「スロット」にプラグインするかを指定するものです。 */

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
