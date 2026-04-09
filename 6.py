import hashlib
import time
import random
import string
from sage.crypto.mq.rijndael_gf import RijndaelGF

def xor_hex(a, b):
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    result = bytes(x ^^ y for x, y in zip(a_bytes, b_bytes))
    return result.hex()

def average_hash_time(hash_func, trials=1000):
    start = time.time()
    for _ in range(trials):
        msg = ''.join(random.choices(string.ascii_letters, k=16)).encode()
        hash_func(msg).hexdigest()
    return (time.time() - start) / trials

def znajdz_kolizje(hash_func, max_time_sec, hash_len_hex):
    start = time.time()
    seen = {}
    while time.time() - start < max_time_sec:
        msg = ''.join(random.choices(string.ascii_letters + string.digits, k=16)).encode()
        digest = hash_func(msg).hexdigest()[:hash_len_hex]
        if digest in seen:
            print(f"\nKolizja! Skrót: {digest}")
            print(f" - Msg1: {seen[digest]}")
            print(f" - Msg2: {msg}")
            return msg, seen[digest]
        seen[digest] = msg
    print(f"\nBrak kolizji w {max_time_sec}s dla długości {hash_len_hex} hex.")
    return None, None

def zadanie1():
    print("ZADANIE 1:\n")
    funkcje = {
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256
    }

    for nazwa, f in funkcje.items():
        t = average_hash_time(f)
        print(f"[{nazwa}] Średni czas skrótu: {t:.6f} s")

    max_czas = 30
    dlugosci = [6,7,8,9,10,11,12,13,14]
    for nazwa, f in funkcje.items():
        print(f"\n[{nazwa}] Szukanie kolizji:")
        for l in dlugosci:
            print(f"- {l*4} bitów ({l} hex):")
            znajdz_kolizje(f, max_czas, l)

def cbc_mac(key_hex, message_blocks_hex):
    aes = RijndaelGF(Nb=4, Nk=4)  
    prev = '0' * 32  
    for block in message_blocks_hex:
        xored = xor_hex(prev, block)
        prev = aes.encrypt(xored, key_hex, format='hex')
    return prev

def hmac_hash(hash_func, key_bytes, msg_bytes):
    block_size = 64
    if len(key_bytes) > block_size:
        key_bytes = hash_func(key_bytes).digest()
    key_bytes = key_bytes.ljust(block_size, b'\x00')
    o_key_pad = bytes([b ^^ 0x5c for b in key_bytes])
    i_key_pad = bytes([b ^^ 0x36 for b in key_bytes])
    return hash_func(o_key_pad + hash_func(i_key_pad + msg_bytes).digest()).hexdigest()

def zadanie2():
    print("\nZADANIE 2: ")

    #CBC-MAC
    klucz_cbc = '00112233445566778899aabbccddeeff'
    bloki = ['00112233445566778899aabbccddeeff', 'ffeeddccbbaa99887766554433221100']
    tag_cbc = cbc_mac(klucz_cbc, bloki)
    print(f"[CBC-MAC] Tag: {tag_cbc}")

    #HMAC 
    klucz_hmac = b'secretkey'
    wiadomosc = b'Dmytro Stefko WAT'
    tag_hmac = hmac_hash(hashlib.sha256, klucz_hmac, wiadomosc)
    print(f"[HMAC-SHA256] Tag: {tag_hmac}")

#zadanie1()
zadanie2()
