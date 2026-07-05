"""
mitm_payload_monitor.py
=======================
Monitor de payload cifrado del keylogger en tiempo real.
Proyecto U2 - Seguridad Informática | Máquina: ParrotMITM (10.0.4.5)

Descripción
-----------
Captura paquetes TCP en el puerto 4444 usando scapy y muestra en pantalla
el payload cifrado interceptado en formato hex+ASCII.
No intenta descifrar el contenido — solo muestra los bytes ilegibles tal
como viajan por la red, demostrando que el cifrado AES-256-GCM es efectivo.

Formato del payload (protocolo del keylogger):
    [4  bytes]  Header big-endian con la longitud total del mensaje
    [12 bytes]  Nonce AES-GCM (aleatorio por cada envío)
    [N  bytes]  Ciphertext + Tag GCM (16 bytes de autenticación al final)

Uso (en ParrotMITM, requiere root para captura raw):
    sudo python3 keylogger/mitm_payload_monitor.py

Dependencias:
    pip install scapy --break-system-packages
"""

import sys
import time
import struct

try:
    from scapy.all import sniff, TCP, IP, Raw
except ImportError:
    print("[ERROR] scapy no instalado. Ejecuta:")
    print("        pip install scapy --break-system-packages")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────────────────────

IFACE           = "enp0s3"   # Interfaz de red de ParrotMITM
KEYLOGGER_PORT  = 4444       # Puerto C2 del keylogger
VICTIM_IP       = "10.0.4.8" # IP de la víctima Ubuntu
C2_IP           = "10.0.4.4" # IP del servidor C2 Parrot

# Tamaños según el protocolo definido en keylogger.py / server.py
HEADER_LEN  = 4   # bytes big-endian con longitud del payload
NONCE_LEN   = 12  # bytes de nonce AES-GCM


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS DE FORMATO
# ──────────────────────────────────────────────────────────────────────────────

def hex_dump(data: bytes, width: int = 16) -> str:
    """
    Genera un volcado hexadecimal del estilo de Wireshark/xxd.

    Formato de cada línea:
        OFFSET  HH HH HH HH ... HH HH  |AAAAAAAAAAAAAAAA|

    Parámetros
    ----------
    data  : bytes  Datos a mostrar.
    width : int    Bytes por línea (default 16).

    Retorno
    -------
    str  Volcado hex multilínea formateado.
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part   = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        # Alinear la columna ASCII aunque el último bloque sea incompleto
        padding = '   ' * (width - len(chunk))
        lines.append(f"    {i:04x}  {hex_part}{padding}  |{ascii_part}|")
    return '\n'.join(lines)


def parse_keylogger_header(payload: bytes) -> dict:
    """
    Intenta interpretar los primeros bytes del payload según el protocolo
    del keylogger (header 4 bytes + nonce 12 bytes).

    Parámetros
    ----------
    payload : bytes  Payload TCP raw.

    Retorno
    -------
    dict con claves:
        'length_declared' : int   Longitud declarada en el header.
        'nonce_hex'       : str   Nonce AES-GCM en hex (si hay >= 16 bytes).
        'ciphertext_len'  : int   Bytes restantes tras el nonce.
    """
    info = {}
    if len(payload) >= HEADER_LEN:
        try:
            info['length_declared'] = struct.unpack('>I', payload[:HEADER_LEN])[0]
        except struct.error:
            info['length_declared'] = None

    if len(payload) >= HEADER_LEN + NONCE_LEN:
        nonce = payload[HEADER_LEN : HEADER_LEN + NONCE_LEN]
        info['nonce_hex'] = nonce.hex()
        info['ciphertext_len'] = len(payload) - HEADER_LEN - NONCE_LEN
    else:
        info['nonce_hex'] = None
        info['ciphertext_len'] = None

    return info


def separator(char: str = '─', width: int = 65) -> str:
    """Retorna una línea separadora de longitud fija."""
    return char * width


# ──────────────────────────────────────────────────────────────────────────────
# CALLBACK DE CAPTURA
# ──────────────────────────────────────────────────────────────────────────────

def on_packet(pkt) -> None:
    """
    Callback invocado por scapy por cada paquete capturado que pasa
    el filtro BPF 'tcp port 4444'.

    Solo procesa paquetes con payload real (Raw layer); ignora
    paquetes de control TCP (SYN, ACK, FIN) sin datos.

    Parámetros
    ----------
    pkt : scapy.packet.Packet  Paquete capturado.
    """
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    tcp     = pkt[TCP]
    ip_hdr  = pkt[IP]
    payload = bytes(pkt[Raw])

    if len(payload) == 0:
        return

    ts  = time.strftime('%H:%M:%S')
    src = f"{ip_hdr.src}:{tcp.sport}"
    dst = f"{ip_hdr.dst}:{tcp.dport}"

    # ── Determinar dirección del paquete ──────────────────────────────────────
    if tcp.dport == KEYLOGGER_PORT:
        # Víctima → C2 (el paquete lleva el payload cifrado del keylogger)
        direction = f"VÍCTIMA → C2   [{src}  →  {dst}]"
        label     = "PAYLOAD CIFRADO AES-256-GCM (keylogger → C2)"
        is_keylogger_data = True
    else:
        # C2 → Víctima (probablemente el ACK de 4 bytes del servidor)
        direction = f"C2 → VÍCTIMA   [{src}  →  {dst}]"
        label     = "RESPUESTA / ACK del servidor C2"
        is_keylogger_data = False

    # ── Cabecera del bloque ───────────────────────────────────────────────────
    print(f"\n{separator('═')}")
    print(f"  [{ts}]  {direction}")
    print(f"  {label}")
    print(f"  Tamaño total capturado: {len(payload)} bytes")

    # ── Desglose del protocolo (solo para paquetes víctima → C2) ─────────────
    if is_keylogger_data and len(payload) > HEADER_LEN:
        info = parse_keylogger_header(payload)
        print(separator())
        print("  DESGLOSE DEL PROTOCOLO KEYLOGGER:")
        if info.get('length_declared') is not None:
            print(f"    • Header  (4 bytes)  → longitud declarada : {info['length_declared']} bytes")
        if info.get('nonce_hex') is not None:
            print(f"    • Nonce  (12 bytes)  → {info['nonce_hex']}")
        if info.get('ciphertext_len') is not None:
            print(f"    • Ciphertext + Tag   → {info['ciphertext_len']} bytes (ilegible sin la clave AES)")

    # ── Volcado hex completo ──────────────────────────────────────────────────
    print(separator())
    print(f"  VOLCADO HEX ({len(payload)} bytes):")
    print(hex_dump(payload))
    print(separator('═'))


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Punto de entrada del script.
    Muestra el banner de inicio y arranca la captura con scapy.
    """
    bpf_filter = f"tcp port {KEYLOGGER_PORT}"

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       MONITOR DE PAYLOAD CIFRADO — MITM Keylogger           ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Interfaz  : {IFACE:<48}║")
    print(f"║  Filtro    : {bpf_filter:<48}║")
    print(f"║  Víctima   : {VICTIM_IP:<48}║")
    print(f"║  C2        : {C2_IP:<48}║")
    print("║  Nota      : Los datos son ILEGIBLES sin la clave AES-256   ║")
    print("║  Salir     : Ctrl+C                                          ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    try:
        sniff(
            iface=IFACE,
            filter=bpf_filter,
            prn=on_packet,
            store=False,        # No acumula paquetes en RAM
        )
    except KeyboardInterrupt:
        print("\n[INFO] Monitor detenido por el usuario.")
    except PermissionError:
        print("\n[ERROR] Se requieren privilegios root.")
        print("        Ejecuta: sudo python3 keylogger/mitm_payload_monitor.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
