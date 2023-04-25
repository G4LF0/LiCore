import hashlib
import binascii
import firebase_admin
from firebase_admin import db


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


def verify_ecdsa_signature(r, s, m, n, G, Q, a):
    # Paso 1: Verify que r y s esten en el intervalo [1, n-1]
    if not (1 <= r < n and 1 <= s < n):
        return 'Step 1 Failed'

    # Paso 2: Hashear mensaje con SHA-256 y convertirlo a decimal
    hash_object = hashlib.sha256()
    hash_object.update(m.encode())
    hexa = binascii.hexlify(hash_object.digest())
    e = int(hexa, 16)

    # Paso 3: Computar w = s^-1 mod n
    w = calc_inv(s, n)

    # Paso 4: Computar u1 = (e * w) mod n and u2 = (r * w) mod n
    u1 = (e * w) % n
    u2 = (r * w) % n

    # Paso 5: Computar X = u1G + u2Q
    x1, y1 = mult_binaria(G[0], G[1], a, p, u1)
    x2, y2 = mult_binaria(Q[0], Q[1], a, p, u2)
    pend = pendiente(x1, y1, x2, y2, a, p)
    x3, y3 = suma_de_la_curva(x1, y1, x2, y2, pend, p)

    # Paso 6: If X == O, rechazar la firma
    if (x3, y3) == (0, 0):
        return 'Rechazar firma'

    # Paso 7: Computar v = x3 mod n
    v = x3 % n
    # Step 8: Aceptar la firma si y solo si v = r
    return v == r

with open('centro_de_control.txt') as f:
    CC_url = f.readlines()

# Las credenciales que se comparten son para uso único de aquellos con acceso al repositorio, no compartir a terceros sin consultar.
cred_object = firebase_admin.credentials.Certificate('receiving-hashes-credentials.json')
default_app = firebase_admin.initialize_app(cred_object, {
    'databaseURL': CC_url[0]
})

# Get Public Production key
Public_prod_key = db.reference("Public Prod key").get()
Ux_Prod = int(Public_prod_key['Ux'],16)
Uy_Prod = int(Public_prod_key['Uy'],16)

# Get Public Consumption key
Public_cons_key = db.reference("Public Cons key").get()
Ux_Cons = int(Public_cons_key['Ux'],16)
Uy_Cons = int(Public_cons_key['Uy'],16)

my_ref = db.reference()
paquetes = db.reference().get()

# Eliminamos del diccionario a iterar las llaves públicas, ya se guardaron y no se podrán verificar en la iteración de paquetes
del paquetes['Public Cons key']
del paquetes['Public Prod key']

p = int(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
a = int(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = int(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
gx = int(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)
gy = int(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = int(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
x = int(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721)

# Separamos diccionario original en dos diccionarios, uno que solo contenga datos de producción y otro que solo contenga datos de consumo
prod_dict = {key: value for key, value in paquetes.items() if "Prod" in key}
cons_dict = {key: value for key, value in paquetes.items() if "Cons" in key}

# Validando firmas para datos de producción
for i in prod_dict:
  r = int(paquetes[i]['Key']['r'],16)
  s = int(paquetes[i]['Key']['s'],16)
  m = paquetes[i]['Dato']
  if verify_ecdsa_signature(r,s,m,n,(gx,gy),(Ux_Prod,Uy_Prod),a):
    print(str(i)+' status: Verified')
  else:
    print(str(i)+' status: Failed Verification')

print()

# Validando firmas para datos de consumo
for i in cons_dict:
  r = int(paquetes[i]['Key']['r'],16)
  s = int(paquetes[i]['Key']['s'],16)
  m = paquetes[i]['Dato']
  if verify_ecdsa_signature(r,s,m,n,(gx,gy),(Ux_Cons,Uy_Cons),a):
    print(str(i)+' status: Verified')
  else:
    print(str(i)+' status: Failed Verification')



