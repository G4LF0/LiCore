import hashlib
import random
import binascii

def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def calc_inv(a, Zn):
    gcd, x, y = extended_gcd(a, Zn)
    if gcd != 1:
        return False
    return x % Zn


def inv_aditivo(x, p):
    if x <= p - 1:
        return p - x
    if x > p:
        return p - (x % p)


def exp_binaria(x, n):
    resultado = 1
    q = n - 2
    while q > 0:
        if q % 2 == 1:
            resultado = (resultado * x) % n
        x = (x * x) % n
        q = q // 2
    return resultado


def pendiente(x1, y1, x2, y2, a, p):
    if (x1 and y1) is None or (x2, y2) is None:
        return (x1, y1) or (x2, y2)
    if (x1 == x2 and y1 == y2):
        return (((3 * x1 * x1) + a) * exp_binaria(2 * y1, p)) % p
    else:
        return ((y2 + inv_aditivo(y1, p)) * exp_binaria(x2 + inv_aditivo(x1, p), p)) % p


def suma_de_la_curva(x1, y1, x2, y2, s, p):
    x3 = 0
    y3 = 0

    x3 = (s * s + inv_aditivo(x1, p) + inv_aditivo(x2, p)) % p
    y3 = (s * (x1 + inv_aditivo(x3, p)) + inv_aditivo(y1, p)) % p
    return x3, y3


def mult_binaria(x, y, a, p, n):
    n = bin(n)[3:]
    x2 = x
    y2 = y
    for i in n:
        if i == '1':
            s = pendiente(x2, y2, x2, y2, a, p)
            x2, y2 = suma_de_la_curva(x2, y2, x2, y2, s, p)
            s = pendiente(x2, y2, x, y, a, p)
            x2, y2 = suma_de_la_curva(x, y, x2, y2, s, p)

        if i == '0':
            s = pendiente(x2, y2, x2, y2, a, p)
            x2, y2 = suma_de_la_curva(x2, y2, x2, y2, s, p)

    return x2, y2

def get_private_key():
    n = int(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    #return random.randint(1,10000000)
    return random.randint(1,n-1)


def sign_message(message, private_key):
    # Definiendo curva NIST P-256
    p = int(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
    a = int(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
    b = int(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
    gx = int(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)
    gy = int(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    n = int(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    x = private_key
    Pub_key_x, Pub_key_y = mult_binaria(gx,gy,a,p,x)
    # = 1

    k = random.randint(1,n-1)
    # k = int(0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60)
    x1, y1 = mult_binaria(gx, gy, a, p, k)
    r = x1 % n

    # Se regresa al paso 1 en caso de que r==0
    if r == 0:
        return sign_message(message, private_key)

    # Generando k inversa
    k_inv = calc_inv(k, n)
    # k_inv = pow(k,-1,n)
    # Convirtiendo mensaje hasheado a entero
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    hexa = binascii.hexlify(hash_object.digest())
    e = int(hexa,16)
    s = (k_inv * (e + x * r)) % n

    # Se regresa al paso 1 en caso de que s==0
    if s == 0:
        return sign_message(message, private_key)
    return (r, s)

def get_gx():
    return int(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)

def get_gy():
    return int(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def get_p():
    return int(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)

def get_a():
    return int(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
