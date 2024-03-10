from django.shortcuts import render
from django.http import JsonResponse

import os
#import threading
import nmap
import subprocess
import socket

from pysnmp.hlapi import *
import platform
import psutil
import getpass
import threading
import paramiko
import time
import concurrent.futures
from pythonping import ping
#import netifaces

from datetime import datetime

from pysnmp.smi import compiler

from scapy.all import ARP, Ether, srp

#from pysnmp.hlapi import *
# Create your views here.

def index(request):
    return render(request, "home.html")

def scan_network(request):
    os.environ['NMAP_PATH'] = 'C:\\Program Files (x86)\\Nmap\\nmap.exe'
    nm = nmap.PortScanner()
    # Escanea tu red local (puedes ajustar el rango de direcciones IP según tu red)
    nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')

    # Obtiene las direcciones IP de los hosts encontrados
    host_list = []
    for host in nm.all_hosts():
        host_list.append(host)

    # Devuelve las direcciones IP como respuesta JSON
    return JsonResponse({'hosts': host_list})

def buscar_ipsx(ip_adress):
	comando="ping -c 1 "+ip_adress
	response=os.popen(comando).read()
	if "1 received" in response:
		print("Encontrado en: ",ip_adress)

for ip in range(1,254):
	current_ip="192.168.1."+str(ip)
	run=threading.Thread(target=buscar_ipsx, args = (current_ip,))
	run.start()

ip_address = "192.168.1.147"

def buscar_ip(ip_address):
    comando = ["ping", "-c", "1", "192.168.1.147"]
    try:
        subprocess.run(comando, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return "192.168.1.147"
    except subprocess.CalledProcessError:
        return None

def scan_network(request):
    found_ips = []

    def buscar_ips():
        for ip in range(1, 254):
            current_ip = "192.168.1." + str(ip)
            result = buscar_ip(current_ip)
            if result:
                found_ips.append(result)

    threads = []
    for _ in range(10):  # Crear 10 hilos para escanear la red
        thread = threading.Thread(target=buscar_ips)
        thread.start()
        threads.append(thread)

    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()

    return JsonResponse({'hosts': found_ips})




def obtener_hostname(ip):
    try:
        return ip, socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip, ip  # Si no se puede obtener el nombre de host, usar la dirección IP

def escanear_red_view(request):
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.1/24', arguments='-sn')

    # Lista de IPs encontradas
    ips_en_red = []

    # Generar tuplas (IP, Nombre de host) utilizando múltiples hilos
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_ip = {executor.submit(obtener_hostname, host): host for host in nm.all_hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                hostname = future.result()[1]
                ips_en_red.append({'ip': ip, 'hostname': hostname})
            except Exception as exc:
                ips_en_red.append({'ip': ip, 'hostname': ip})  # Si hay un error, usar la dirección IP como nombre de host

    # Devuelve las IPs encontradas
    return JsonResponse({'ips': ips_en_red})




#########################################
def obtener_info_ip(ip):
    info = {}

    # Información del sistema operativo
    info['sistema_operativo'] = platform.system()

    # Información de almacenamiento
    particiones = psutil.disk_partitions()
    info['almacenamiento'] = {}
    for particion in particiones:
        uso = psutil.disk_usage(particion.mountpoint)
        info['almacenamiento'][particion.mountpoint] = {
            'total': convertir_a_gb(uso.total),
            'disponible': convertir_a_gb(uso.free),
            'ocupado': convertir_a_gb(uso.used)
        }

    # Información de memoria RAM
    memoria = psutil.virtual_memory()
    info['memoria_ram'] = {
        'total': convertir_a_gb(memoria.total),
        'disponible': convertir_a_gb(memoria.available),
        'usada': convertir_a_gb(memoria.used)
    }

    # Modelo del equipo, arquitectura
    info['modelo'] = platform.machine()
    info['arquitectura'] = platform.architecture()

    # Información del usuario
    info['usuario'] = getpass.getuser()

    # Información del procesador
    info['nucleos'] = psutil.cpu_count(logical=False)
    info['velocidad_procesador'] = psutil.cpu_freq()

    # Información de red
    try:
        interfaces = netifaces.interfaces()
        info['red'] = {}
        for interface in interfaces:
            ifaddresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in ifaddresses:
                ipv4_info = ifaddresses[netifaces.AF_INET][0]
                info['red'][interface] = {
                    'ip': ipv4_info['addr'],
                    'mascara': ipv4_info['netmask'],
                    'puerta_enlace': ipv4_info.get('broadcast', '')
                }
    except Exception as e:
        print("Error al obtener información de red:", e)

    return info

def obtener_info_equipo(request, ip):
    informacion = obtener_info_ip(ip)
    return JsonResponse(informacion)

def info_equipo(request, ip):
    ip_info = obtener_info_ip(ip)
    return render(request, 'info_device.html', {'ip_info': ip_info})


def convertir_a_gb(bytes_valor):
    return round(bytes_valor / (1024 ** 3), 2)

######################################################

def info_ip(request, ip):
    print(f"Solicitando información para IP: {ip}")
    informacion = obtener_info_ip(ip)
    print("Información obtenida:", informacion)
    return JsonResponse(informacion)

##################################################
def estado_ips(request):
    ips = ['192.168.1.147', '192.168.1.183', '192.168.1.1']
    estados = {}

    for ip in ips:
        try:
            response = ping(ip, count=1, timeout=1)
            if response.success():
                estado = "Activo"
            else:
                estado = "Inactivo"
        except Exception as e:
            estado = "Inactivo (Error)"

        estados[ip] = estado

    return JsonResponse(estados)

def ip_active(request):
    return render(request, 'ip_active.html')

##################################################

def escanear_redx(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]

    dispositivos = []
    for sent, received in result:
        dispositivos.append({'ip': received.psrc, 'mac': received.hwsrc})

    return dispositivos

# Ejemplo de uso
def mostrar_dispositivos(request):
    ip_range = "192.168.1.1/24"  # Cambiar a la subred de tu red local
    dispositivos_en_red = escanear_redx(ip_range)
    return render(request, 'view_device.html', {'dispositivos': dispositivos_en_red})

##################################################
def obtener_informacion_snmp(ip, comunidad, *oids):
    for oid in oids:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                   CommunityData(comunidad),
                   UdpTransportTarget((ip, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )
        if error_indication:
            print(error_indication)
        elif error_status:
            print('%s at %s' % (error_status.prettyPrint(), error_index and var_binds[int(error_index) - 1][0] or '?'))
        else:
            for var_bind in var_binds:
                print(' = '.join([x.prettyPrint() for x in var_bind]))

def mostrar_informacion_hardware(request):
    ip_dispositivo = '192.168.1.183'  # Dirección IP del dispositivo SNMP
    comunidad = 'public'  # Nombre de comunidad SNMP
    oid_hostname = ObjectIdentity('SNMPv2-MIB', 'sysName', 0)
    oid_descripcion = ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
    oid_cpu = ObjectIdentity('HOST-RESOURCES-MIB', 'hrProcessorLoad', 0)
    oid_memoria_total = ObjectIdentity('UCD-SNMP-MIB', 'memTotalReal', 0)
    oid_memoria_usada = ObjectIdentity('UCD-SNMP-MIB', 'memAvailReal', 0)
    oid_interfaces = ObjectIdentity('IF-MIB', 'ifTable')

    # Obtener el nombre del dispositivo
    obtener_informacion_snmp(ip_dispositivo, comunidad, oid_hostname)

    # Obtener la descripción del dispositivo
    obtener_informacion_snmp(ip_dispositivo, comunidad, oid_descripcion)

    # Obtener el uso de CPU
    obtener_informacion_snmp(ip_dispositivo, comunidad, oid_cpu)

    # Obtener información de la memoria
    obtener_informacion_snmp(ip_dispositivo, comunidad, oid_memoria_total, oid_memoria_usada)

    # Obtener información de interfaces
    obtener_informacion_snmp(ip_dispositivo, comunidad, oid_interfaces)

    return JsonResponse({'message': 'Información de hardware obtenida. Ver la consola para detalles.'})