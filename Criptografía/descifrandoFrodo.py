from statistics import mean
from base64 import b64encode, b64decode
import re


english_frequency = {
    b'a': 0.08167,
    b'b': 0.01492,
    b'c': 0.02782,
    b'd': 0.04253,
    b'e': 0.12702,
    b'f': 0.02228,
    b'g': 0.02015,
    b'h': 0.06094,
    b'i': 0.06966,
    b'j': 0.00153,
    b'k': 0.00772,
    b'l': 0.04025,
    b'm': 0.02406,
    b'n': 0.06749,
    b'o': 0.07507,
    b'p': 0.01929,
    b'q': 0.00095,
    b'r': 0.05987,
    b's': 0.06327,
    b't': 0.09056,
    b'u': 0.02758,
    b'v': 0.00978,
    b'w': 0.02360,
    b'x': 0.00150,
    b'y': 0.01974,
    b'z': 0.00074,
}


def otp(data, key):
    out = [(lambda a, b : a ^ b)(*l) for l in zip(data, key)]
    return bytes(out)

def repeatingxor(b, key):
    k = (key * len(b))[0:len(b)]
    return otp(b, k)

def frequency_analysis(text):
    regex = re.compile(b'[^a-zA-Z]')
    alpha = regex.sub(b'', text).decode().lower()
    observed_frequency = { i: 0 for i in list(english_frequency.keys()) }
    for char in alpha:
        observed_frequency[char.encode('ascii')] += 1

    observed_list = list(observed_frequency.values())
    expected_list = list(english_frequency.values())

    meanSqErr = mean([(lambda f1, f2 : (f1-f2)**(2.0))(*l) for l in zip(expected_list, observed_list)])
    spaces = text.count(b' ')
    symbolFreq = 1.0 - ( float(len(alpha) + spaces) / float(len(text)) )
    if symbolFreq > 0.7:
        return 1000
    penalizer = 1.0 + (symbolFreq*7)
    return meanSqErr * penalizer

def transpose(m):
    return [bytes([m[j][i] for j in range(len(m))]) for i in range(len(m[0]))]

def brute_force(group):
    DEBUG = True
    best_k = 0
    best_score = -1
    if (DEBUG):
        print("----------------------------------------------------")
    for i in range(0, 128):
        k = bytes([i])
        plain = repeatingxor(group, k)
        f_score = frequency_analysis(plain)
        if (f_score < 100 and DEBUG):
            print("[" + str(f_score) + "] (" + str(k) + ") " + str(plain))
        if best_score < 0 or f_score < best_score:
            best_k = k
            best_score = f_score
    return best_k

def get_key_many_time_pad(enc_messages):
    groups = transpose(enc_messages)


    key = []
    for g in groups:
        k = brute_force(g)
        key.append(k)
    return b''.join(key)


ciphertextb64 = b'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'
ciphertext = b64decode(ciphertextb64)
listaLetras= []
palabra= b''

#En este bucle for estoy agrupando los bytes de ciphertext en un array con elementos de diez bytes de longitud
for caracter in ciphertext:
    palabra += bytes([caracter])
    if len(palabra) == 10:
        listaLetras.append(palabra)
        palabra= b''

key = get_key_many_time_pad(listaLetras)
print("key found!")
print(key)

#Utilizo la clave encontrada haciendo XOR en cada grupo de 10 bytes del texto encriptado
plaintext= repeatingxor(ciphertext, key)
print(plaintext)
