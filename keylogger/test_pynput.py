"""
test_pynput.py
==============
Script de diagnóstico — verifica que pynput puede capturar teclas en X11.

Ejecutar DESDE LA TERMINAL GRÁFICA DE UBUNTU (no por SSH):
    python3 test_pynput.py

Si captura teclas: pynput funciona correctamente.
Si no captura nada: hay un problema de permisos X11.
"""

import os
import sys

print("=" * 50)
print("  TEST DE CAPTURA DE TECLADO — pynput/X11")
print("=" * 50)
print(f"DISPLAY     : {os.environ.get('DISPLAY', '(no definido)')}")
print(f"XAUTHORITY  : {os.environ.get('XAUTHORITY', '(no definido)')}")
print(f"Python      : {sys.version}")
print("=" * 50)
print("Escribe cualquier tecla (Ctrl+C para salir)...")
print()

try:
    from pynput import keyboard

    def on_press(key):
        try:
            print(f"[CAPTURADO] Tecla: {key.char!r}")
        except AttributeError:
            print(f"[CAPTURADO] Tecla especial: {key}")

    def on_release(key):
        if key == keyboard.Key.esc:
            print("[INFO] ESC presionado — saliendo.")
            return False

    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

except ImportError as e:
    print(f"[ERROR] pynput no instalado: {e}")
    print("Solución: pip install pynput --break-system-packages")

except Exception as e:
    print(f"[ERROR] No se pudo iniciar el listener: {e}")
    print()
    print("Posibles causas:")
    print("  1. Sesión Wayland activa (necesitas X11/Xorg)")
    print("  2. Sin permisos para acceder al display X11")
    print("  3. DISPLAY incorrecto o vacío")
