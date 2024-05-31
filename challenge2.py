import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json, base64

HOST ='130.192.5.212'
PORT =6521
if __name__ == '__main__':
    server = remote(HOST,PORT)

    admin = server.recvline()
    print(admin)
    myname = ""
    server.sendline(myname.encode())
    server.recvline()
    token = server.recvline()
    print("token")
    print(token)
    crypto = token.decode().strip().split(": ")[1]
    print("crypto")
    print(crypto)
    nonce = crypto.split(".")[0]
    print("nonce")
    print(nonce)
    cookie = crypto.split(".")[1]
    print("cookie")
    print(cookie)
    decoded_cookie = base64.b64decode(cookie)
    decoded_nonce = base64.b64decode(nonce)
    print(decoded_cookie)
    print(len(decoded_cookie))
    print(decoded_nonce)
    print(len(decoded_nonce))
    default_cookie = json.dumps({
        "username": myname
    })
    admin = json.dumps({
        "admin": True
    })
    print(len(admin.encode()))
    print(default_cookie.encode())


    keystream = bytes(a ^ b for (a, b) in zip(decoded_cookie, default_cookie.encode()))
    new_cookie = bytes(a ^ b for (a, b) in zip(keystream, admin.encode()))
    cookie_to_send = base64.b64encode(new_cookie).decode()
    new_token = nonce+"."+cookie_to_send
    print(new_token)
    idk = server.recvline()
    print(idk)
    #server.sendline(new_token.encode())
    idk = server.recvline()
    print(idk)
    idk = server.recvline()
    print(idk)
    idk = server.recvline()
    print(idk)
    flag = "flag"
    server.sendline(flag.encode())
    idk = server.recvline()
    print(idk)
    server.sendline(new_token.encode())
    idk = server.recvline()
    print(idk)
    idk = server.recvline()
    print(idk)
    idk = server.recvline()
    print(idk)