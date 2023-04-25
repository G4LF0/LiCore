# Codigo hecho con ayuda del repositorio de vishal-android-freak encontrado en https://github.com/vishal-android-freak/firebase-micropython-esp32/blob/master/ufirebase.py
# Se realizaron modificaciones a la libreria ufirebase.py para proteger datos sensibles del reto
import ufirebase as firebase
import os as MOD_OS
import network as MOD_NETWORK
import time as MOD_TIME
import time
import network
import hashlib
import ubinascii
import binascii
import ECDSA_signature as ecdsa


# Conexion a wifi realizada con ayuda del repositorio de WoolDoughnut310 en https://github.com/WoolDoughnut310/micropython-firebase-auth
# Conectando a red wifi
wlan = network.WLAN(network.STA_IF)
wlan.active(True)
if not wlan.isconnected():
    wlan.connect(firebase.get_wifi_ssid(), firebase.get_wifi_password())
    print("Waiting for Wi-Fi connection", end="...")
    while not wlan.isconnected():
        print(".", end="")
        time.sleep(1)
    print()

wlan_sta = network.WLAN(network.STA_IF)
wlan_sta.active(True)
wlan_mac = wlan_sta.config('mac')
MAC_add = ubinascii.hexlify(wlan_mac).decode()

pk = ecdsa.get_private_key()
Ux, Uy = ecdsa.mult_binaria(ecdsa.get_gx(), ecdsa.get_gy(), ecdsa.get_a(), ecdsa.get_p(), pk)
firebase.setURL(firebase.get_centro_de_control())
firebase.put("Public Prod key", {"Ux" : hex(Ux), "Uy" : hex(Uy) }, bg=0)

# Bucle que accedera a los 364 datos disponibles para trazas de consumo
for j in range(364):
    
    # Se fijan las credenciales para acceder a la base de datos originales
    firebase.setURL(firebase.get_base_de_datos())
    
    # Se realiza la petición del dato con index j a la base de datos
    firebase.get('Prod_'+str(j), "var1", bg=0)
    current_day = firebase.var1
    
    # El contador así como la actualizacion de su valor, nos ayudará a tener registros sobre la hora de los datos.
    cont = 0
    
    # Se fijan las credenciales para acceder al centro de control
    firebase.setURL(firebase.get_centro_de_control())
    print('----- DAY ' + str(j+1) + ' -----')
    
    # Se crea bucle que accedera a los 96 datos disponibles dentro del dato j-esimo
    for i in range(1,97):
        
        # Se crea el ID del dato específico
        curr_str = "{}-{}-{} {:02d}:{:02d}/{}_{}={}".format(current_day['Anio'], current_day['Mes '], current_day['Dia'], int(cont/60), cont%60, current_day['ID'], current_day['ConsProd'], current_day[str(i)])
        curr_str = MAC_add + " " + curr_str
        # Se crea un objeto de tipo hashlib.sha256() para hashear el ID, realizado con ayuda de documentacion encontrada en https://docs.python.org/3.5/library/hashlib.html
        hash_object = hashlib.sha256()
        hash_object.update(curr_str)
        hexa = binascii.hexlify(hash_object.digest())

        # Firmado con ECDSA
        r, s = ecdsa.sign_message(curr_str,pk)
        
        # Se crea el paquete de datos a enviar al centro de control
        data = {
        "Dato": curr_str,
        "hash": hexa,
        "Key": {'r': hex(r),'s': hex(s)}
        }
        
        # Se crea el public ID del paquete de datos
        #public_id = '1 '+curr_str[2:16]
        public_id = "Prod_" + str(j+1) + '_' + str(i)
        
        # Se realiza la petición para escribir datos sobre el centro de control.
        firebase.put(public_id, data, bg=0)
        cont +=15
