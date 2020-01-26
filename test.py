import subprocess,time

data=[]
for _ in range(100):
    t1=time.time()
    subprocess.call(["./scripts/script_ryu-manager.sh"])
    t2=time.time()
    
    print(t2-t1)
    data.append(t2-t1)
print("min/avg/max:{}/{}/{}".format(min(data),sum(data)/len(data),max(data)))
