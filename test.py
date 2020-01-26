import subprocess,time

def run_and_capture(cmd):
    '''
    :param cmd: str 実行するコマンド.
    :rtype: str
    :return: 標準出力.
    '''
    # ここでプロセスが (非同期に) 開始する.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    buf = []
    a=[b'loading app TcpSyn_comment.py\n', b'loading app ryu.controller.ofp_handler\n', b'instantiating app TcpSyn_comment.py of TCPSYN13\n', b'instantiating app ryu.controller.ofp_handler of OFPHandler\n', b'BRICK TCPSYN13\n', b'  CONSUMES EventOFPPacketIn\n', b'  CONSUMES EventOFPSwitchFeatures\n', b'BRICK ofp_event\n', b"  PROVIDES EventOFPPacketIn TO {'TCPSYN13': {'main'}}\n", b"  PROVIDES EventOFPSwitchFeatures TO {'TCPSYN13': {'config'}}\n", b'  CONSUMES EventOFPEchoReply\n', b'  CONSUMES EventOFPEchoRequest\n', b'  CONSUMES EventOFPErrorMsg\n', b'  CONSUMES EventOFPHello\n', b'  CONSUMES EventOFPPortDescStatsReply\n', b'  CONSUMES EventOFPPortStatus\n', b'  CONSUMES EventOFPSwitchFeatures\n']


    while True:
        # バッファから1行読み込む.
        line = proc.stdout.readline()
        buf.append(line)

        # バッファが空 + プロセス終了.
        if buf==a:
            break
    proc.terminate()
    print("terminate()")

data=[]
for _ in range(100):
    t1=time.time()
    run_and_capture(["./scripts/script_ryu-manager.sh"])
    t2=time.time()
    
    print(t2-t1)
    data.append(t2-t1)
print("min/avg/max:{}/{}/{}".format(min(data),sum(data)/len(data),max(data)))
