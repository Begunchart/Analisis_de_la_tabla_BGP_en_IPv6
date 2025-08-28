import requests
import json
import csv
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import ipaddress
import bisect
from functools import lru_cache
from collections import Counter
from queue import Queue
import os
import traceback
from collections import defaultdict

rir_prefijos={} #En esta variable almacenamos los prefijos segun IANA para cada RIR
archivo_csv_iana="ipv6-unicast-address-assignments.csv"

# ==================== CONSTANTES ====================
MAX_THREADS = 254

# ==================== ESTRUCTURAS DE DATOS ====================
_DELEGATED_DATA = {
    'asn': {},    # {'rir': [(start, end)]}
    'ipv6': {}     # {'rir': [IPv6Network]}
}


# ==================== FUNCIONES DE CARGA ====================
def _load_delegated_data():
    """Carga el archivo delegated-extended en memoria"""
    global _DELEGATED_DATA
    try:
        # Verificar y descargar el archivo si no existe
        if not os.path.exists('delegated-extended'):
            print("Descargando delegated-extended-latest...")
            try:
                url = "https://ftp.ripe.net/pub/stats/ripencc/delegated-extended-latest"
                response = requests.get(url, timeout=30)
                with open('delegated-extended', 'w') as f:
                    f.write(response.text)
                print("Descarga completada exitosamente")
            except Exception as download_error:
                print(f"Error al descargar delegated-extended: {str(download_error)}")
                return False

        # Procesar el archivo
        with open('delegated-extended', 'r') as f:
            for line in f:
                if line.startswith('#') or '|' not in line:
                    continue
                    
                parts = line.strip().split('|')
                if len(parts) < 6:
                    continue
                    
                # Mantener RIR en minúsculas (como aparece en el archivo)
                rir = parts[0].lower()  # <- Cambio clave aquí
                
                # Normalización especial para RIPENCC
                if rir == 'ripencc':
                    rir = 'ripe'
                    
                type_ = parts[2]
                start = parts[3]
                size = parts[4]
                
                if type_ == 'asn':
                    try:
                        start_asn = int(start.replace('AS', '').replace('as', ''))
                        size_int = int(size)
                        end_asn = start_asn + size_int - 1
                        _DELEGATED_DATA['asn'].setdefault(rir, []).append((start_asn, end_asn))
                    except ValueError:
                        continue
                        
                elif type_ == 'ipv6':
                    try:
                        network = ipaddress.IPv6Network(f"{start}/{size}")
                        _DELEGATED_DATA['ipv6'].setdefault(rir, []).append(network)
                    except ValueError:
                        continue

        # Ordenar rangos para búsqueda binaria
        for rir in _DELEGATED_DATA['asn']:
            _DELEGATED_DATA['asn'][rir].sort()
            
        print("\nDatos RIR cargados exitosamente:")
        print(f"- Rangos ASN cargados: {sum(len(v) for v in _DELEGATED_DATA['asn'].values())}")
        print(f"- Redes IPv6 cargadas: {sum(len(v) for v in _DELEGATED_DATA['ipv6'].values())}")
        
        # Debug: mostrar algunos ejemplos
        print("\nEjemplos de RIRs cargados (minúsculas):")
        for rir in ['apnic', 'arin', 'lacnic', 'afrinic', 'ripe']:
            if rir in _DELEGATED_DATA['asn']:
                print(f"{rir}: {len(_DELEGATED_DATA['asn'][rir])} rangos ASN")
            if rir in _DELEGATED_DATA['ipv6']:
                print(f"{rir}: {len(_DELEGATED_DATA['ipv6'][rir])} redes IPv6")
                
        return True
        
    except Exception as e:
        print(f"\nError crítico en _load_delegated_data(): {str(e)}")
        traceback.print_exc()
        return False

# ==================== FUNCIÓN PRINCIPAL DE BÚSQUEDA ====================
@lru_cache(maxsize=500000)
def FindinAPI(VALUE):
    RIR_MAPPING = {
        'ripencc': 'RIPE',
        'apnic': 'APNIC',
        'arin': 'ARIN',
        'lacnic': 'LACNIC',
        'afrinic': 'AFRINIC'
    }

    try:
        # Para IPv6
        if ':' in VALUE:
            try:
                network_str = VALUE.split('/')[0] if '/' in VALUE else VALUE
                ip = ipaddress.IPv6Address(network_str)
                for rir, networks in _DELEGATED_DATA['ipv6'].items():
                    for net in networks:
                        if ip in net:
                            #print(f"DEBUG: Prefijo {VALUE} encontrado en {rir} (red {net})")
                            return RIR_MAPPING.get(rir.lower(), rir.upper())
            except ipaddress.AddressValueError:
                print(f"DEBUG: Formato IPv6 inválido: {VALUE}")
                return "UNKNOWN"

        # Para ASNs
        else:
            clean_asn = ''.join(c for c in VALUE if c.isdigit())
            if clean_asn:
                asn_num = int(clean_asn)
                for rir, ranges in _DELEGATED_DATA['asn'].items():
                    starts = [r[0] for r in ranges]
                    idx = bisect.bisect_right(starts, asn_num) - 1
                    if idx >= 0 and ranges[idx][0] <= asn_num <= ranges[idx][1]:
                        #print(f"DEBUG: ASN {VALUE} encontrado en {rir} (rango {ranges[idx][0]}-{ranges[idx][1]})")
                        return RIR_MAPPING.get(rir.lower(), rir.upper())

    except Exception as e:
        print(f"Error en FindinAPI({VALUE}): {str(e)}")

    print(f"DEBUG: No se encontró región para {VALUE}")
    return "UNKNOWN"

# ==================== FUNCIONES DE THREADING ====================
def worker():
    while True:
        task = task_queue.get()
        if task is None:
            task_queue.task_done()
            break

        tabla, asn, prefix, task_type = task
        try:
            # Debug: Mostrar qué se está procesando
            #print(f"\nProcesando: ASN={asn}, Prefix={prefix}, Type={task_type}")

            # Asignar región al ASN si es necesario
            if task_type == 'both':
                if 'Region' not in tabla[asn] or not tabla[asn]['Region']:
                    tabla[asn]['Region'] = FindinAPI(asn)
                    #print(f"ASN {asn} asignado a {tabla[asn]['Region']}")

            # Siempre asignar región al prefijo
            if 'Region' not in tabla[asn]['PREFIX'][prefix] or not tabla[asn]['PREFIX'][prefix]['Region']:
                region = FindinAPI(prefix)
                tabla[asn]['PREFIX'][prefix]['Region'] = region
                #print(f"Prefijo {prefix} asignado a {region}")

            # Debug: Verificar asignación
            #print(f"Resultado: ASN Region={tabla[asn].get('Region', 'UNKNOWN')}, Prefix Region={tabla[asn]['PREFIX'][prefix].get('Region', 'UNKNOWN')}")

        except Exception as e:
            print(f"Error en worker: {str(e)}")
            traceback.print_exc()
        finally:
            semaforo.release()
            task_queue.task_done()

def parse_bgp_table(file_path):
    allprefix = []
    bgp_dict = {}
    PREVIOUSPREFIX = ''

    with open(file_path, 'r') as file:
        for line in file:
            if not line or line.startswith(('BGP table', 'Status codes', 'Origin codes', 'Network')):
                continue

            if line[0] == "*":
                PREFIX = line[3:].split(' ')[0].strip()
                if len(PREFIX) >= 4:
                    PREVIOUSPREFIX = PREFIX
            else:
                PREFIX = PREVIOUSPREFIX
                
            try:
                if line[59] == "0":
                    AS_PATH = line[61:-3].split(' ')  
                    if PREFIX and AS_PATH:
                        if AS_PATH[-1] not in bgp_dict:
                            bgp_dict[AS_PATH[-1]] = {
                                'PREFIX': {PREFIX: {'Region': '', 'PATH': [AS_PATH[:-1]]}},
                                'Region': ''
                            }
                            task_queue.put((bgp_dict, AS_PATH[-1], PREFIX, 'both'))
                            semaforo.acquire()
                            allprefix.append(PREFIX)
                        else:
                            if PREFIX not in bgp_dict[AS_PATH[-1]]['PREFIX']:
                                bgp_dict[AS_PATH[-1]]['PREFIX'][PREFIX] = {
                                    'Region': '',
                                    'PATH': [AS_PATH[:-1]]
                                }
                                task_queue.put((bgp_dict, AS_PATH[-1], PREFIX, 'prefix'))
                                semaforo.acquire()
                                allprefix.append(PREFIX)
                            else:
                                bgp_dict[AS_PATH[-1]]['PREFIX'][PREFIX]['PATH'].append(AS_PATH[:-1])
            except Exception:
                pass

    task_queue.join()
    for _ in range(MAX_THREADS):
        task_queue.put(None)
    
    return bgp_dict, list(dict.fromkeys(allprefix))

# ==================== FUNCIONES DE ANÁLISIS ====================

def generar_reporte_compacto(archivo_csv):
    #La funcion recibe un archivo CSV (lista de prefijos IPv6 asignados por IANA a los RIRs)
    #Devuelve un diccionario con el formato RIR:Prefijos
    rir_prefijos = defaultdict(list)
    
    with open(archivo_csv, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        
        for row in csv_reader:
            if len(row) >= 2:  # Asegura que existan las columnas necesarias
                prefijo = row[0].strip()
                rir = row[1].strip()
                
                if prefijo and rir:  # Filtra líneas vacías
                    rir_prefijos[rir].append(prefijo)
    
    return rir_prefijos

def Cantidad_de_48_por_RIR():
    TablaRIRRegionCantidad = {'APNIC': set(), 'ARIN': set(), 'LACNIC': set(), 'IANA':set(),
                             'AFRINIC': set(), 'RIPE': set(), 'BOGON': set(), 'UNKNOWN': set()}

    for asn_data in bgp_tabla_dict.values():
        for prefix, prefix_data in asn_data['PREFIX'].items():
            # Obtener región del PREFIJO (no del ASN)
            region = prefix_data.get('Region', 'UNKNOWN')
            # Si es UNKNOWN, intentar con el ASN
            if region == 'UNKNOWN':
                region = asn_data.get('Region', 'UNKNOWN')
            # Normalizar a mayúsculas
            region = region.upper()
            if region in TablaRIRRegionCantidad:
                TablaRIRRegionCantidad[region].add(prefix)

    prefijos_48_por_RIRs = {'APNIC': 0, 'ARIN': 0, 'LACNIC': 0, 'IANA': 0,
                             'AFRINIC': 0, 'RIPE': 0, 'BOGON': 0, 'UNKNOWN': 0}
    # Contar prefijos /48 por RIR
    for region, prefixes in TablaRIRRegionCantidad.items():
        prefijos_48_por_RIRs[region] = sum(1 for prefix in prefixes if prefix.endswith('/48'))
    return prefijos_48_por_RIRs

def Cantidad_de_48_Global():
    Prefijos = []
    for i in bgp_tabla_dict.keys():
        Prefijos.extend(list(bgp_tabla_dict[i]['PREFIX'].keys()))
    Prefijos = set(Prefijos)
    Cantidad_de_prefijos_48 = sum(1 for prefix in Prefijos if prefix.endswith('/48'))
    return Cantidad_de_prefijos_48

def Promedio_de_Longitud_de_prefijo_por_RIR():
    TablaPromedioPrefijoRIR = {'APNIC': set(), 'ARIN': set(), 'LACNIC': set(), 'IANA':set(),
                             'AFRINIC': set(), 'RIPE': set(), 'BOGON': set(), 'UNKNOWN': set()}

    for asn_data in bgp_tabla_dict.values():
        for prefix, prefix_data in asn_data['PREFIX'].items():
            # Obtener región del PREFIJO (no del ASN)
            region = prefix_data.get('Region', 'UNKNOWN')
            # Si es UNKNOWN, intentar con el ASN
            if region == 'UNKNOWN':
                region = asn_data.get('Region', 'UNKNOWN')
            # Normalizar a mayúsculas
            region = region.upper()
            if region in TablaPromedioPrefijoRIR:
                TablaPromedioPrefijoRIR[region].add(prefix)
    
    for region in TablaPromedioPrefijoRIR.keys():
        Suma_de_longitudes = sum(int(prefix.split('/')[1]) for prefix in TablaPromedioPrefijoRIR[region])
        if len(TablaPromedioPrefijoRIR[region]) == 0:
            TablaPromedioPrefijoRIR[region] = 0
        else:
            TablaPromedioPrefijoRIR[region] = round(Suma_de_longitudes / len(TablaPromedioPrefijoRIR[region]),2)
    return TablaPromedioPrefijoRIR

def Promedio_de_Longitud_de_prefijo_Global():
    Prefijos = []
    for i in bgp_tabla_dict.keys():
        Prefijos.extend(list(bgp_tabla_dict[i]['PREFIX'].keys()))
    Prefijos = set(Prefijos)
    Cantidad_de_prefijos = len(Prefijos)
    Suma_de_longitudes = sum(int(prefix.split('/')[1]) for prefix in Prefijos)
    return round(Suma_de_longitudes / Cantidad_de_prefijos,2)

def confederaciones_AS():
    """Retorna el número de AS-SETs encontrados"""
    as_sets = [asn for asn in bgp_tabla_dict if asn.startswith('{')]
    return len(as_sets)

def contar_BOGON():
    for AS in bgp_tabla_dict.keys():
        if AS == "::/0" or (int(AS)>=64512 and int(AS)<=65534) or (int(AS)>=4200000000 and int(AS)<=4294967295) or (bgp_tabla_dict[AS]['Region']=="IANA"):
            bgp_tabla_dict[AS]['Region'] = 'BOGON'

def PATH_global_mas_largo():
    PATHGlobal = 0
    longest_length = 0
    for key, value in bgp_tabla_dict.items():
        path = value["PREFIX"].values()
        for prefix in path:
            current_path = prefix["PATH"]
            for arr in current_path:
                if len(arr) > longest_length:
                    longest_length = len(arr)
            if PATHGlobal < longest_length:
                PATHGlobal = longest_length
    return PATHGlobal

def PATH_RIR_mas_largo():
    TablaRIRPATHLongest = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    longest_length = 0
    for key, value in bgp_tabla_dict.items():
        path = value["PREFIX"].values()
        for prefix in path:
            current_path = prefix["PATH"]
            for arr in current_path:
                try:
                    if len(arr) > TablaRIRPATHLongest[prefix["Region"]]:
                        TablaRIRPATHLongest[prefix["Region"]] = len(arr)
                except:
                    pass
    return TablaRIRPATHLongest

def prefijos_a_nivel_global():
    Prefijos = []
    for i in bgp_tabla_dict.keys():
        Prefijos.extend(list(bgp_tabla_dict[i]['PREFIX'].keys()))
    return len(set(Prefijos))

def prefijos_por_RIR():
    TablaRIRRegionCantidad = {'APNIC': set(), 'ARIN': set(), 'LACNIC': set(), 'IANA':set(),
                             'AFRINIC': set(), 'RIPE': set(), 'BOGON': set(), 'UNKNOWN': set()}

    for asn_data in bgp_tabla_dict.values():
        for prefix, prefix_data in asn_data['PREFIX'].items():
            # Obtener región del PREFIJO (no del ASN)
            region = prefix_data.get('Region', 'UNKNOWN')
            # Si es UNKNOWN, intentar con el ASN
            if region == 'UNKNOWN':
                region = asn_data.get('Region', 'UNKNOWN')
            # Normalizar a mayúsculas
            region = region.upper()
            if region in TablaRIRRegionCantidad:
                TablaRIRRegionCantidad[region].add(prefix)

    return {rir: len(prefixes) for rir, prefixes in TablaRIRRegionCantidad.items()}

def AS_a_nivel_global():
    return len(bgp_tabla_dict.keys())

def AS_a_nivel_de_RIR():
    TablaASRegionCantidad = {'APNIC': 0, 'ARIN': 0, 'LACNIC': 0, 
                            'AFRINIC': 0, 'RIPE': 0, 'BOGON': 0, 'UNKNOWN': 0}

    for asn, asn_data in bgp_tabla_dict.items():
        region = asn_data.get('Region', 'UNKNOWN').upper()
        if region in TablaASRegionCantidad:
            TablaASRegionCantidad[region] += 1
        else:
            # Si la región no está en el mapeo, verificar el prefijo
            for prefix_data in asn_data['PREFIX'].values():
                pref_region = prefix_data.get('Region', 'UNKNOWN').upper()
                if pref_region in TablaASRegionCantidad:
                    TablaASRegionCantidad[pref_region] += 1
                    break

    return TablaASRegionCantidad

def promedio_prefijos_por_AS_mundial(CantidadGlobalPrefijos, CantidadGlobalAS):
    return round(CantidadGlobalPrefijos / CantidadGlobalAS, 2)

def promedio_prefijos_por_AS_por_RIR(TablaRIRRegionCantidad, TablaASRegionCantidad):
    TablaPromedioASPrefijosRIR = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for i in TablaPromedioASPrefijosRIR.keys():
        try:
            TablaPromedioASPrefijosRIR[i] = round(TablaRIRRegionCantidad[i]/TablaASRegionCantidad[i], 2)
        except:
            pass
    return TablaPromedioASPrefijosRIR

def AS_de_32_bits_a_nivel_mundial():
    """Maneja ASN normales y AS-SETs ({X,Y})"""
    prefix_32 = []
    AS_32 = []
    
    for asn in bgp_tabla_dict:
        # Limpiar y separar AS-SETs
        clean_asn = asn.strip('{}').split(',')[0]  # Toma el primer AS del set
        
        try:
            if int(clean_asn) > 65535:
                prefix_32.extend(list(bgp_tabla_dict[asn]['PREFIX'].keys()))
                AS_32.append(asn)
        except ValueError:
            print(f"ASN no numérico ignorado: {asn}")
            continue
    
    return len(set(prefix_32)), AS_32

def AS_de_32_bits_por_RIR(AS_32):
    Tabla_AS_32_bits_Region = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for i in AS_32:
        try:
            Tabla_AS_32_bits_Region[bgp_tabla_dict[i]["Region"]] += 1
        except:
            pass
    return Tabla_AS_32_bits_Region

def AS_solo_transito():
    #El nombre de esta funcion es medio mentiroso. Esta funcion trabaja los ASs que hacen
    #transito y procesa devuelve varios valores
    all_paths = []
    AS_Transit = []
    for asn, data in bgp_tabla_dict.items():
        for prefix, prefix_data in data.get("PREFIX", {}).items():
            paths = prefix_data.get("PATH", [])
            for path in paths:
                all_paths.extend(path)
                path_aux = path[1:-1]
                for AS in path_aux:
                    if not(AS == asn):
                        AS_Transit.append(AS)
    AS_Transit_Final = set(AS_Transit)
    AS_Transit_Only = []
    AS_Transit_Anuncio = []
    AS_Transit_Anuncio_por_RIR = {'APNIC': 0, 'ARIN': 0, 'LACNIC': 0, 'IANA': 0,
                             'AFRINIC': 0, 'RIPE': 0, 'BOGON': 0, 'UNKNOWN': 0}
    Lista_AS = list(bgp_tabla_dict.keys())
    for AS in AS_Transit_Final:
        if not(AS in Lista_AS):
            AS_Transit_Only.append(AS)
        else:
            AS_Transit_Anuncio.append(AS)
            AS_Transit_Anuncio_por_RIR[bgp_tabla_dict[AS]['Region']] += 1
    return AS_Transit_Only, len(AS_Transit_Only), len(AS_Transit_Anuncio), AS_Transit_Final, AS_Transit_Anuncio_por_RIR


def AS_transito_entre_16_32_bits(AS_Transit_Only):
    AS_Transit_Only_16 = []
    AS_Transit_Only_32 = []
    for AS in AS_Transit_Only:
        if int(AS) > 65535:
            AS_Transit_Only_32.append(AS)
        else:
            AS_Transit_Only_16.append(AS)
    return AS_Transit_Only_16, AS_Transit_Only_32, len(AS_Transit_Only_16), len(AS_Transit_Only_32)

def AS_transito_por_RIR(AS_Transit_Only_16, AS_Transit_Only_32):
    Transit_Only_16_bits_RIR = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for AS in AS_Transit_Only_16:
        try:
            Transit_Only_16_bits_RIR[FindinAPI(AS)] += 1
        except:
            pass
    Transit_Only_32_bits_RIR = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for AS in AS_Transit_Only_32:
        try:
            Transit_Only_32_bits_RIR[FindinAPI(AS)] += 1
        except:
            pass
    return Transit_Only_16_bits_RIR, Transit_Only_32_bits_RIR

def AS_de_solo_origen(AS_Transit_Final):
    AS_Origin_Only = []
    for asn in bgp_tabla_dict:
        if not(asn in AS_Transit_Final):
            AS_Origin_Only.append(asn)
    return AS_Origin_Only, len(AS_Origin_Only)

def AS_de_solo_origen_16_y_32_bits(AS_Origin_Only):
    AS_Origin_Only_16 = []
    AS_Origin_Only_32 = []
    for AS in AS_Origin_Only:
        if AS[0] != "{" and int(AS) > 65535:
            AS_Origin_Only_32.append(AS)
        else:
            AS_Origin_Only_16.append(AS)
    return AS_Origin_Only_16, AS_Origin_Only_32, len(AS_Origin_Only_16), len(AS_Origin_Only_32)

def AS_de_solo_origen_16_y_32_bits_por_RIR(AS_Origin_Only_16, AS_Origin_Only_32):
    Origin_Only_16_bits_RIR = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for AS in AS_Origin_Only_16:
        try:
            Origin_Only_16_bits_RIR[bgp_tabla_dict[AS]['Region']] += 1
        except:
            pass
    Origin_Only_32_bits_RIR = {'APNIC':0,'ARIN':0,'LACNIC':0,'AFRINIC':0,'RIPE':0,'BOGON':0}
    for AS in AS_Origin_Only_32:
        try:
            Origin_Only_32_bits_RIR[bgp_tabla_dict[AS]['Region']] += 1
        except:
            pass
    return Origin_Only_16_bits_RIR, Origin_Only_32_bits_RIR

def prefijo_con_mas_prepend():
    Prefijo_Prepend_Global = {'PREFIX':"",'Count':0,'AS':""}
    Prefijo_Prepend_por_RIR = {'APNIC': {'PREFIX':"",'Count':0,'AS':""}, 'ARIN': {'PREFIX':"",'Count':0,'AS':""}, 'LACNIC': {'PREFIX':"",'Count':0,'AS':""}, 'IANA': {'PREFIX':"",'Count':0,'AS':""},
                             'AFRINIC': {'PREFIX':"",'Count':0,'AS':""}, 'RIPE': {'PREFIX':"",'Count':0,'AS':""}, 'BOGON': {'PREFIX':"",'Count':0,'AS':""}, 'UNKNOWN': {'PREFIX':"",'Count':0,'AS':""}}
    for asn, data in bgp_tabla_dict.items():
        for prefix, prefix_data in data.get("PREFIX", {}).items():
            paths = prefix_data.get("PATH", [])
            region = prefix_data.get("Region")
            for path in paths:
                if path:
                    AS, cont = Counter(path).most_common(1)[0]
                    if cont > Prefijo_Prepend_Global['Count']:
                        Prefijo_Prepend_Global.update({'PREFIX': prefix, 'Count': cont, 'AS': AS})
                    if cont > Prefijo_Prepend_por_RIR[region]['Count']:
                        Prefijo_Prepend_por_RIR[region].update({'PREFIX': prefix, 'Count': cont, 'AS': AS})
                    
    return Prefijo_Prepend_Global, Prefijo_Prepend_por_RIR

# ==================== FUNCIÓN DE ENVÍO DE CORREO ====================
def enviar_correo(destinatario, asunto, contenido):
    #remitente = "<YOUR EMAIL>"
    #password = "<YOUR PASSWORD>"
    remitente = "<YOUR EMAIL>"
    password = "<YOUR PASSWORD>"

    mensaje = MIMEMultipart()
    mensaje['From'] = remitente
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto
    mensaje.attach(MIMEText(contenido, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(remitente, password)
        server.sendmail(remitente, destinatario, mensaje.as_string())
        print(f"Correo enviado a {destinatario}!")
    except Exception as e:
        print(f"Error al enviar a {destinatario}: {str(e)}")
    finally:
        server.quit()

# ==================== EJECUCIÓN PRINCIPAL ====================
if __name__ == "__main__":
    # Inicialización
    if not _load_delegated_data():
        exit(1)

    # Configuración de threading
    semaforo = threading.Semaphore(MAX_THREADS)
    task_queue = Queue()
    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    # Procesamiento principal
    bgp_table_dict, allprefix = parse_bgp_table('bgptable.txt')
    
    with open("BGP_table.json", "w") as f:
        json.dump(bgp_table_dict, f, indent=4)

    # Cargar datos para análisis
    global bgp_tabla_dict  # Hacerla global para las funciones de análisis
    with open('BGP_table.json', 'r') as f:
        bgp_tabla_dict = json.load(f)

    # Análisis
    PATHGlobal = PATH_global_mas_largo()
    TablaRIRPATHLongest = PATH_RIR_mas_largo()
    CantidadGlobalPrefijos = prefijos_a_nivel_global()
    AS_SET = confederaciones_AS()
    cant_prefijos_32, AS_32 = AS_de_32_bits_a_nivel_mundial()
    TablaRIRRegionCantidad = prefijos_por_RIR()
    CantidadGlobalAS = AS_a_nivel_global()
    TablaASRegionCantidad = AS_a_nivel_de_RIR()
    PromedioASPrefijosGlobal = promedio_prefijos_por_AS_mundial(CantidadGlobalPrefijos,CantidadGlobalAS)
    TablaPromedioASPrefijosRIR = promedio_prefijos_por_AS_por_RIR(TablaRIRRegionCantidad,TablaASRegionCantidad)
    CantidadGlobalPrefijos_32,AS_32 = AS_de_32_bits_a_nivel_mundial()
    CantidadGlobalAS_32 = len(AS_32)
    Tabla_AS_32_bits_Region = AS_de_32_bits_por_RIR(AS_32)
    AS_Transit_Only,AS_Transit_Only_Num,AS_Transit_Anuncio_Num,AS_Transit_Final,Num_AS_Transit_per_RIR_also_announce = AS_solo_transito()
    AS_Transit_Only_16,AS_Transit_Only_32,AS_Transit_Only_16_Num,AS_Transit_Only_32_Num = AS_transito_entre_16_32_bits(AS_Transit_Only)
    Transit_Only_16_bits_RIR,Transit_Only_32_bits_RIR = AS_transito_por_RIR(AS_Transit_Only_16, AS_Transit_Only_32)
    AS_Origin_Only,AS_Origin_Only_Num = AS_de_solo_origen(AS_Transit_Final)
    AS_Origin_Only_16,AS_Origin_Only_32,AS_Origin_Only_16_Num,AS_Origin_Only_32_Num = AS_de_solo_origen_16_y_32_bits(AS_Origin_Only)
    Origin_Only_16_bits_RIR,Origin_Only_32_bits_RIR = AS_de_solo_origen_16_y_32_bits_por_RIR(AS_Origin_Only_16, AS_Origin_Only_32)
    Prefijo_Prepend_Global, Prefijo_Prepend_por_RIR = prefijo_con_mas_prepend()
    Promedio_de_Longitud_de_prefijo_Global = Promedio_de_Longitud_de_prefijo_Global()
    TablaPromedioPrefijoRIR=Promedio_de_Longitud_de_prefijo_por_RIR()
    Global_Cantidad_de_prefijos_48 = Cantidad_de_48_Global()
    Cantidad_de_48_por_RIR = Cantidad_de_48_por_RIR()
    rir_prefijos=generar_reporte_compacto(archivo_csv_iana)


    print (TablaRIRRegionCantidad)
    # Generación y envío de correo
    contenido_correo = f"""
    This is an automated weekly mailing describing the state of the Global
IPv6 Routing Table as seen from Potaroo.net (https://bgp.potaroo.net/v6/as2.0/bgptable.txt)

The posting is sent to VENOG.
If you wish to be added please send an email to: info.venog@gmail.com

Global Analysis Summary
--------------------------------------------------------------------------------------

  BGP routing table entries examined: {CantidadGlobalPrefijos}
    Prefix with the most prepends: {Prefijo_Prepend_Global}
    Unidentified prefixes: {TablaRIRRegionCantidad["UNKNOWN"]}
    Number of AS_SET found in the Routing Table: {AS_SET}
    Longest Global AS PATH: {PATHGlobal}
    Prefixes identified as IANA: {TablaRIRRegionCantidad["IANA"]}
    Global Average Prefix Length: {Promedio_de_Longitud_de_prefijo_Global}
    Number of /48s globally: {Global_Cantidad_de_prefijos_48}

  Total ASes present in the Internet Routing Table: {CantidadGlobalAS}
    Average number of ASes per prefix: {PromedioASPrefijosGlobal}

    Number of 32-bit ASes globally: {CantidadGlobalAS_32}
    Number of 16-bit ASes globally: {CantidadGlobalAS - CantidadGlobalAS_32}

    Number of ASes that are only origin: {AS_Origin_Only_Num}
      Number of 16-bit ASes that are only origin: {AS_Origin_Only_16_Num}
      Number of 32-bit ASes that are only origin: {AS_Origin_Only_32_Num}

    Number of ASes that are only transit: {AS_Transit_Only_Num}
      Number of 16-bit ASes that are only transit: {AS_Transit_Only_16_Num}
      Number of 32-bit ASes that are only transit: {AS_Transit_Only_32_Num}

    Number of Transit ASes that also announce prefixes: {AS_Transit_Anuncio_Num}

    Number of bogon 16-bit ASNs visible in the Routing Table: {TablaASRegionCantidad["BOGON"] - Tabla_AS_32_bits_Region["BOGON"]}

    Number of bogon 32-bit ASNs visible in the Routing Table: {Tabla_AS_32_bits_Region["BOGON"]}

    Unidentified ASes: {TablaASRegionCantidad["UNKNOWN"]}

APNIC Region Analysis Summary
--------------------------------------------------------------------------------------

  APNIC IPv6 prefixes: {' '.join(rir_prefijos['APNIC'])}

  Number of prefixes analyzed in APNIC: {TablaRIRRegionCantidad["APNIC"]}
    Average number of prefixes according to the number of ASes in APNIC: {TablaPromedioASPrefijosRIR["APNIC"]}
    Average Prefix Length in APNIC: {TablaPromedioPrefijoRIR["APNIC"]}
    Number of /48s in APNIC: {Cantidad_de_48_por_RIR["APNIC"]}
    Longest PATH in APNIC: {TablaRIRPATHLongest["APNIC"]}
    Prefix with most prepends in APNIC {Prefijo_Prepend_por_RIR["APNIC"]}

  Number of ASes in APNIC: {TablaASRegionCantidad["APNIC"]}
    Number of 32-bit ASes in APNIC: {Tabla_AS_32_bits_Region["APNIC"]}
    Number of 16-bit ASes that are only origin in APNIC: {Origin_Only_16_bits_RIR["APNIC"]}
    Number of 32-bit ASes that are only origin in APNIC: {Origin_Only_32_bits_RIR["APNIC"]}
    Number of 16-bit ASes that are only transit in APNIC: {Transit_Only_16_bits_RIR["APNIC"]}
    Number of 32-bit ASes that are only transit in APNIC: {Transit_Only_32_bits_RIR["APNIC"]}
    Number of Transit ASes that also announce prefixes in APNIC: {Num_AS_Transit_per_RIR_also_announce["APNIC"]}

ARIN Region Analysis Summary
--------------------------------------------------------------------------------------

  ARIN IPv6 prefixes: {' '.join(rir_prefijos['ARIN'])}

  Number of prefixes analyzed in ARIN: {TablaRIRRegionCantidad["ARIN"]}
    Average number of prefixes according to the number of ASes in ARIN: {TablaPromedioASPrefijosRIR["ARIN"]}
    Average Prefix Length in ARIN: {TablaPromedioPrefijoRIR["ARIN"]}
    Number of /48s in ARIN: {Cantidad_de_48_por_RIR["ARIN"]}
    Longest AS PATH in ARIN: {TablaRIRPATHLongest["ARIN"]}
    Prefix with most prepends in ARIN {Prefijo_Prepend_por_RIR["ARIN"]}

  Number of ASes in ARIN: {TablaASRegionCantidad["ARIN"]}
    Number of 32-bit ASes in ARIN: {Tabla_AS_32_bits_Region["ARIN"]}
    Number of 16-bit ASes that are only origin in ARIN: {Origin_Only_16_bits_RIR["ARIN"]}
    Number of 32-bit ASes that are only origin in ARIN: {Origin_Only_32_bits_RIR["ARIN"]}
    Number of 16-bit ASes that are only transit in ARIN: {Transit_Only_16_bits_RIR["ARIN"]}
    Number of 32-bit ASes that are only transit in ARIN: {Transit_Only_32_bits_RIR["ARIN"]}
    Number of Transit ASes that also announce prefixes in ARIN: {Num_AS_Transit_per_RIR_also_announce["ARIN"]}

LACNIC Region Analysis Summary
--------------------------------------------------------------------------------------

  LACNIC IPv6 prefixes: {' '.join(rir_prefijos['LACNIC'])}

  Number of prefixes analyzed in LACNIC: {TablaRIRRegionCantidad["LACNIC"]}
    Average number of prefixes according to the number of ASes in LACNIC: {TablaPromedioASPrefijosRIR["LACNIC"]}
    Average Prefix Length in LACNIC: {TablaPromedioPrefijoRIR["LACNIC"]}
    Number of /48s in LACNIC: {Cantidad_de_48_por_RIR["LACNIC"]}
    Longest AS PATH in LACNIC: {TablaRIRPATHLongest["LACNIC"]}
    Prefix with most prepends in LACNIC {Prefijo_Prepend_por_RIR["LACNIC"]}

  Number of ASes in LACNIC: {TablaASRegionCantidad["LACNIC"]}
    Number of 32-bit ASes in LACNIC: {Tabla_AS_32_bits_Region["LACNIC"]}
    Number of 16-bit ASes that are only origin in LACNIC: {Origin_Only_16_bits_RIR["LACNIC"]}
    Number of 32-bit ASes that are only origin in LACNIC: {Origin_Only_32_bits_RIR["LACNIC"]}
    Number of 16-bit ASes that are only transit in LACNIC: {Transit_Only_16_bits_RIR["LACNIC"]}
    Number of 32-bit ASes that are only transit in LACNIC: {Transit_Only_32_bits_RIR["LACNIC"]}
    Number of Transit ASes that also announce prefixes in LACNIC: {Num_AS_Transit_per_RIR_also_announce["LACNIC"]}

AFRINIC Region Analysis Summary
--------------------------------------------------------------------------------------
  
  AFRINIC IPv6 prefixes: {' '.join(rir_prefijos['AFRINIC'])}

  Number of prefixes analyzed in AFRINIC: {TablaRIRRegionCantidad["AFRINIC"]}
    Average number of prefixes according to the number of ASes in AFRINIC: {TablaPromedioASPrefijosRIR["AFRINIC"]}
    Average Prefix Length in AFRINIC: {TablaPromedioPrefijoRIR["AFRINIC"]}
    Number of /48s in AFRINIC: {Cantidad_de_48_por_RIR["AFRINIC"]}
    Longest AS PATH in AFRINIC: {TablaRIRPATHLongest["AFRINIC"]}
    Prefix with most prepends in AFRINIC {Prefijo_Prepend_por_RIR["AFRINIC"]}

  Number of ASes in AFRINIC: {TablaASRegionCantidad["AFRINIC"]}
    Number of 32-bit ASes in AFRINIC: {Tabla_AS_32_bits_Region["AFRINIC"]}
    Number of 16-bit ASes that are only origin in AFRINIC: {Origin_Only_16_bits_RIR["AFRINIC"]}
    Number of 32-bit ASes that are only origin in AFRINIC: {Origin_Only_32_bits_RIR["AFRINIC"]}
    Number of 16-bit ASes that are only transit in AFRINIC: {Transit_Only_16_bits_RIR["AFRINIC"]}
    Number of 32-bit ASes that are only transit in AFRINIC: {Transit_Only_32_bits_RIR["AFRINIC"]}
    Number of Transit ASes that also announce prefixes in AFRINIC: {Num_AS_Transit_per_RIR_also_announce["AFRINIC"]}

RIPE Region Analysis Summary
---------------------------------------------------------------------------------

  RIPE IPv6 prefixes: {' '.join(rir_prefijos['RIPE NCC'])}

  Number of prefixes analyzed in RIPE: {TablaRIRRegionCantidad["RIPE"]}
    Average number of prefixes according to the number of ASes in RIPE: {TablaPromedioASPrefijosRIR["RIPE"]}
    Average Prefix Length in RIPE: {TablaPromedioPrefijoRIR["RIPE"]}
    Number of /48s in RIPE: {Cantidad_de_48_por_RIR["RIPE"]}
    Longest AS PATH in RIPE: {TablaRIRPATHLongest["RIPE"]}
    Prefix with most prepends in RIPE {Prefijo_Prepend_por_RIR["RIPE"]}

  Number of ASes in RIPE: {TablaASRegionCantidad["RIPE"]}
    Number of 32-bit ASes in RIPE: {Tabla_AS_32_bits_Region["RIPE"]}
    Number of 16-bit ASes that are only origin in RIPE: {Origin_Only_16_bits_RIR["RIPE"]}
    Number of 32-bit ASes that are only origin in RIPE: {Origin_Only_32_bits_RIR["RIPE"]}
    Number of 16-bit ASes that are only transit in RIPE: {Transit_Only_16_bits_RIR["RIPE"]}
    Number of 32-bit ASes that are only transit in RIPE: {Transit_Only_32_bits_RIR["RIPE"]}
    Number of Transit ASes that also announce prefixes in RIPE: {Num_AS_Transit_per_RIR_also_announce["RIPE"]}


End of report
Based in Phil Smith's IPv4 Weekly Report

"""
    
    destinatarios = [
        "diego@molina-aquino.com",
        "alejandro@lacnic.net",
        "guillermohernandezguoze@gmail.com",
        "astolk@ula.ve", "venog@googlegroups.com"
    ]
    #destinatarios = ["alejandro@lacnic.net"]

    asunto = "Weekly Global IPv6 Routing Table Summary"
    for destinatario in destinatarios:
        enviar_correo(destinatario, asunto, contenido_correo)

    print("Proceso completado exitosamente!")
    os._exit(0)

os._exit(0)

