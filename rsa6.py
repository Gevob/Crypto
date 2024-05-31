import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import gmpy2
from Crypto.Util.number import bytes_to_long, getPrime, inverse, long_to_bytes

HOST ='130.192.5.212'
PORT =6646

if __name__ == '__main__':
    server = remote(HOST,PORT)
    c = server.recvline()
    print(c)

    plain1 = '5'*48
    plain2 = '6' * 48
    input1 = "e" + str(plain1)
    input2 = "e" + str(plain2)
    server.sendline(input1.encode())
    c1 = server.recvline()
    server.sendline(input2.encode())
    c2 = server.recvline()
    n = gmpy2.gcd(pow(int(plain1),65537)-int(c1.decode()),pow(int(plain2),65537)-int(c2.decode()))
    pad = pow(2,65537,n)
    newval = int(c.decode()) * pad % n
    input = "d"+str(newval)
    server.sendline(input.encode())
    f = server.recvline()
    print(long_to_bytes(int(f.decode()) // 2))