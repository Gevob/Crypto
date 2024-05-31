import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json, base64
from Crypto.Util.number import bytes_to_long, getPrime, inverse, long_to_bytes

HOST ='130.192.5.212'
PORT =6645
if __name__ == '__main__':
    server = remote(HOST,PORT)
    n = server.recvline()
    print(n)
    c = server.recvline()
    print(c)
    pad = pow(2,65537,int(n.decode()))
    newval = int(c.decode()) * pad % int(n.decode())
    input = "d"+str(newval)
    server.sendline(input.encode())
    f = server.recvline()
    print(long_to_bytes(int(f.decode()) // 2))



