import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST ='130.192.5.212'
PORT =6531
if __name__ == '__main__':
    server = remote(HOST,PORT)
    for i in range(128):
        number_C = server.recvline()
        #print(number_C)
        otp_string = server.recvline()
        #print(otp_string)
        otp = otp_string.decode().strip().split(": ")[1]
        server.sendline(otp.encode())
        whichone = server.recvline()
        cypher = whichone.decode().strip().split(": ")[2].encode()
        print(cypher)
        if cypher[:32] == cypher[32:]:
            type = "ECB"
            #print("ECB")
        else:
            type = "CBC"
            #print("CBC")
        idk= server.recvline()
        #print(idk)
        server.sendline(type.encode())
        next = server.recvline()
        print(i)

    flag = server.recvline()
    print(flag)