from Crypto import Random
from Crypto.Cipher import AES
from Block.ctr import aes_ctr
from secrets import token_bytes, randbits


class SuperSafeServer:
    def __init__(self):
        self._key = token_bytes(AES.key_size[0])
        self._nonce = randbits(64)

    def create_cookie(self, user_data):
        if ';' in user_data or '=' in user_data:
            raise Exception("Caracteres ilegales en user data")
        cookie_string = "cookieversion=2.0;userdata=" + user_data + ";safety=veryhigh"
        return aes_ctr(cookie_string.encode(), self._key, self._nonce)

    def check_admin(self, cookie):
        cookie_string = aes_ctr(cookie, self._key, self._nonce).decode()
        return ';admin=true;' in cookie_string

def otp(data, key):
    out = [(lambda a, b : a ^ b)(*l) for l in zip(data, key)]
    return out


def forge_cookie():
    server = SuperSafeServer()
    user_data = "x" # Rellenamos el campo para generar la clave que nos da la cookie
    cookie = server.create_cookie(user_data)
    user_data = b"x"
    plaintext= b"cookieversion=2.0;userdata=" + user_data + b";safety=veryhigh"
    key= otp(bytes(cookie), plaintext)#Se obtiene la clave generada por el servidor, que encripta la cookie, a través de XOR
    admin_injection= b"cookieversion=2.0;userdata=;admin=true;safety=veryhigh"
    cipher_malicioso= otp(key, admin_injection)
    if server.check_admin(cipher_malicioso):
        print("Acceso Admin!")

forge_cookie()
