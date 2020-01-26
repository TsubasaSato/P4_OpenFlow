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

    while True:
        # バッファから1行読み込む.
        line = proc.stdout.readline()
        buf.append(line)
        print(buf)

        # バッファが空 + プロセス終了.
        if not line and proc.poll() is not None:
            break

    return ''.join(buf)

data=[]
for _ in range(100):
    t1=time.time()
    run_and_capture(["./scripts/script_ryu-manager.sh"])
    t2=time.time()
    
    print(t2-t1)
    data.append(t2-t1)
print("min/avg/max:{}/{}/{}".format(min(data),sum(data)/len(data),max(data)))
