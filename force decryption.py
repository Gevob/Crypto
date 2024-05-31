import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST ='130.192.5.212'
PORT =6523

if __name__ == '__main__':
    server = remote(HOST, PORT)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    server.sendline(b"enc")
    message = server.recvline()
    print(message)
    p = b"0"*16
    server.sendline(p.hex().encode())
    message = server.recvline()
    print(message)
    IV = bytes.fromhex(message.decode().strip().split(": ")[1])
    print(IV)
    message = server.recvline()
    print(message)
    C = bytes.fromhex(message.decode().strip().split(": ")[1])
    print(C)
    xor1 = bytes(a ^ b for (a, b) in zip(IV, p))
    #xor2 = bytes(a ^ b for (a, b) in zip(xor1, IV))
    xor3 = bytes(a ^ b for (a, b) in zip(xor1, b"mynamesuperadmin"))
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    message = server.recvline()
    print(message)
    server.sendline(b"dec")
    message = server.recvline()
    print(message)
    server.sendline(C.hex().encode())
    message = server.recvline()
    print(message)
    server.sendline(xor3.hex().encode())
    message = server.recvline()
    print(message)