# Historial de Chat — Proyecto U2 Seguridad Informática

**Fecha:** 2026-07-02 / 2026-07-03 / 2026-07-04
**Proyecto:** Desarrollo de Keylogger con Cifrado, Transmisión Segura y Evasión
**Repositorio:** [BorisMejiasII/ProyectoSeguridadU2_BorisMejias](https://github.com/BorisMejiasII/ProyectoSeguridadU2_BorisMejias)

---

## 📁 Archivos del Proyecto

```
Proyecto U2/
├── historial_chat.md                          ← este archivo
├── README.md                                  ← documentación completa
├── Proyecto_Unidad_2_Seguridad (2026).pdf     ← enunciado original
├── keylogger/
│   ├── keylogger.py          → keylogger Ubuntu 24.04 (X11 + AES-256-GCM)
│   ├── server.py             → servidor C2 Parrot Linux
│   ├── decrypt_backup.py     → descifra backups locales
│   ├── build.py              → compila con PyInstaller → binario ELF
│   ├── requirements.txt      → pynput, cryptography, pyinstaller, python-xlib
│   ├── test_pynput.py        → script de diagnóstico X11/pynput
│   └── mitm_demo.cap         → caplet bettercap para demo MITM
└── informe_amenaza/
    └── threat_report.md      → informe técnico de amenaza (Ejercicio 4)
```

---

## 🏗️ Arquitectura del Laboratorio

```
Tu PC (Windows) ──── editas código ──── GitHub ☁️

VirtualBox
├── VM 1: Parrot Linux  (ATACANTE / C2)   IP: 10.0.4.4
│         → python3 server.py
│
├── VM 2: Ubuntu 24.04  (VÍCTIMA)         IP: 10.0.4.8
│         → ./dist/wsh (keylogger compilado)
│         → IMPORTANTE: iniciar sesión en "Ubuntu on Xorg" (X11, NO Wayland)
│
└── VM 3: ParrotMITM (INTERCEPTOR)        IP: 10.0.4.5 (estática, configurada con nmcli)
          → sudo bettercap -iface enp0s3 -caplet keylogger/mitm_demo.cap
```

**Red:** Red NAT de VirtualBox — todas las VMs se ven entre sí.
**Gateway NAT:** 10.0.4.1

---

## 📋 Estado del Proyecto

### ✅ Ejercicio 1 — Keylogger (20 pts) — COMPLETADO Y PROBADO
- Captura de teclado con `pynput` backend X11
- Persistencia XDG Autostart: `~/.config/autostart/gnome-session-helper.desktop`
- Documentación completa con docstrings
- Probado: teclas capturadas correctamente en Ubuntu X11

### ✅ Ejercicio 2 — Cifrado AES-256-GCM + Envío C2 (20 pts) — COMPLETADO Y PROBADO
- Cifrado AES-256-GCM con nonce aleatorio por chunk
- Envío TCP cada 30 segundos a Parrot C2
- Servidor C2 en Parrot descifra y guarda en `logs/received.log`
- Probado: logs descifrados llegando correctamente a Parrot con `tail -f`

### ✅ Ejercicio 3 — MITM + Evasión (20 pts) — PARCIALMENTE COMPLETADO
- ✅ ARP spoofing con bettercap funcionando (ParrotMITM intercepta tráfico Ubuntu→Parrot)
- ✅ Tráfico visible pero cifrado/ilegible en ParrotMITM
- ✅ IP forwarding activo (tráfico sigue llegando a Parrot C2)
- ✅ Binario ELF compilado con PyInstaller (`dist/wsh`)
- ⬜ **Pendiente:** Captura tcpdump mostrando payload cifrado en hex
- ⬜ **Pendiente:** Subir `dist/wsh` a VirusTotal y documentar resultado
- ⬜ **Pendiente:** Hashes SHA-256 y MD5 del ejecutable para el informe

### ⚠️ Ejercicio 4 — Informe Técnico (10 pts) — CASI COMPLETO
- `informe_amenaza/threat_report.md` redactado completo
- ⬜ **Pendiente:** Completar tabla de hashes (SHA-256 y MD5 de `dist/wsh`)

---

## 🔧 Problemas Resueltos y Sus Soluciones

### Bug crítico: server.py importaba keylogger.py (pynput en Parrot)
**Problema:** `server.py` hacía `from keylogger import AES_KEY, decrypt_payload` lo que obligaba
a tener `pynput` instalado en Parrot (innecesario y causaba error).
**Solución:** Se movió `AES_KEY` y `decrypt_payload` directamente a `server.py`.
**Commit:** `116e699`

### Wayland vs X11 en Ubuntu 24.04
**Problema:** Ubuntu 24.04 usa Wayland por defecto. pynput no puede capturar teclado en Wayland.
**Síntoma:** XAUTHORITY contenía `.mutter-Xwaylandauth` en lugar de `.Xauthority`.
**Solución:** Al iniciar sesión en Ubuntu, clic en engranaje ⚙️ → seleccionar "Ubuntu on Xorg".
**Verificación:** `echo $XDG_SESSION_TYPE` debe mostrar `x11`.

### SSH + pynput no funciona
**Problema:** Ejecutar keylogger por SSH daba error de X11 authorization.
**Solución:** Ejecutar `./dist/wsh` directamente desde la terminal gráfica de Ubuntu (no por SSH).

### IP duplicada entre Parrot original y ParrotMITM (clon)
**Problema:** Al clonar Parrot, ambas VMs recibían la misma IP por DHCP (mismo machine-id).
**Solución:** Configurar IP estática en ParrotMITM con NetworkManager:
```bash
sudo nmcli con mod "Wired connection 1" \
  ipv4.addresses "10.0.4.5/24" \
  ipv4.gateway "10.0.4.1" \
  ipv4.dns "8.8.8.8" \
  ipv4.method manual
sudo nmcli con up "Wired connection 1"
```

### Bettercap: comandos pegados todos a la vez no funcionan
**Problema:** Al pegar múltiples comandos en bettercap algunos fallaban con "unknown syntax".
**Solución:** Crear archivo caplet (`mitm_demo.cap`) y ejecutar con:
```bash
sudo bettercap -iface enp0s3 -caplet keylogger/mitm_demo.cap
```

### pip bloqueado en Parrot/Ubuntu (externally-managed-environment)
**Solución:** Agregar flag `--break-system-packages`:
```bash
pip install cryptography --break-system-packages
```

---

## 🚀 Comandos de Uso Rápido

### Tu PC (Windows PowerShell) — para commits:
```powershell
$env:PATH += ";C:\Program Files\GitHub CLI;C:\Program Files\Git\cmd;C:\Program Files\Git\bin"
git add .
git commit -m "descripcion"
git push
```

### Parrot C2 (10.0.4.4):
```bash
cd ~/ProyectoSeguridadU2_BorisMejias/keylogger
python3 server.py
# Segunda terminal para ver logs en tiempo real:
tail -f ~/ProyectoSeguridadU2_BorisMejias/keylogger/logs/received.log
```

### Ubuntu víctima (10.0.4.8):
```bash
# IMPORTANTE: iniciar sesión en "Ubuntu on Xorg", NO en Wayland
# Verificar: echo $XDG_SESSION_TYPE  → debe mostrar x11
cd ~/ProyectoSeguridadU2_BorisMejias/keylogger
./dist/wsh
```

### ParrotMITM (10.0.4.5):
```bash
# Habilitar reenvío de paquetes
sudo sysctl -w net.ipv4.ip_forward=1
# Actualizar repo
cd ~/ProyectoSeguridadU2_BorisMejias && git pull
# Lanzar MITM
sudo bettercap -iface enp0s3 -caplet keylogger/mitm_demo.cap
# Segunda terminal para ver payload cifrado en hex:
sudo tcpdump -i enp0s3 tcp port 4444 -X -n
```

### SSH desde Parrot a Ubuntu (para copiar/pegar comandos en Ubuntu):
```bash
ssh vboxuser@10.0.4.8
```

---

## 📋 Pendiente para la próxima sesión

```
⬜ 1. En Ubuntu: obtener hashes del ejecutable
      sha256sum ~/ProyectoSeguridadU2_BorisMejias/keylogger/dist/wsh
      md5sum ~/ProyectoSeguridadU2_BorisMejias/keylogger/dist/wsh
      → copiar resultados al informe_amenaza/threat_report.md (sección 4.1)

⬜ 2. VirusTotal: subir dist/wsh desde tu PC y documentar resultado
      → ir a https://www.virustotal.com
      → subir el binario
      → captura de pantalla del resultado
      → documentar en README o informe

⬜ 3. tcpdump en ParrotMITM: captura de pantalla mostrando payload hex cifrado
      sudo tcpdump -i enp0s3 tcp port 4444 -X -n
      → evidencia visual del cifrado en tránsito

⬜ 4. Grabar video demostrativo (si lo pide el proyecto)
```

---

## 📊 Pauta de Evaluación

| Criterio | Puntaje | Estado |
|---|---|---|
| **Ej. 1** — Captura de teclado | 8 pts | ✅ |
| **Ej. 1** — Persistencia | 6 pts | ✅ |
| **Ej. 1** — Documentación del código | 4 pts | ✅ |
| **Ej. 1** — Análisis de limitaciones | 2 pts | ✅ |
| **Ej. 2** — Elección y justificación del cifrado | 6 pts | ✅ |
| **Ej. 2** — Gestión de clave | 4 pts | ✅ |
| **Ej. 2** — Envío periódico cifrado | 6 pts | ✅ |
| **Ej. 2** — Descifrado | 4 pts | ✅ |
| **Ej. 3** — Ataque MITM | 6 pts | ✅ (bettercap funcionando) |
| **Ej. 3** — Ejecutable y evasión | 8 pts | ⚠️ (falta VirusTotal) |
| **Ej. 3** — Mitigación | 6 pts | ✅ (en threat_report.md) |
| **Ej. 4** — Completitud del informe | 6 pts | ⚠️ (faltan hashes) |
| **Ej. 4** — Calidad y redacción | 4 pts | ✅ |
| **TOTAL** | **70 pts** | ~60/70 completados |
