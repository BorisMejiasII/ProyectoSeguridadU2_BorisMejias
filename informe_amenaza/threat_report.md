# Threat Intelligence Report

**Clasificación:** TLP:WHITE — Distribución irrestricta  
**Severidad:** Alta  
**Fecha:** 2026-07-02  
**Autor:** Ricardo Pérez — riperez@utalca.cl  
**Versión:** 1.0

---

## 1. Nombre y Descripción de la Amenaza

| Campo | Detalle |
|---|---|
| **Nombre** | WSHLogger |
| **Familia** | Spyware / Keylogger |
| **Plataforma** | Ubuntu 24.04 LTS (Linux x86_64, sesión X11) |
| **Lenguaje** | Python 3.12 → compilado a binario ELF con PyInstaller |
| **Primera detección** | 2026-07 (entorno controlado) |

**WSHLogger** es un keylogger de usuario (user-land) para Linux que captura la totalidad de las pulsaciones de teclado mediante `pynput` con backend X11, cifra el contenido con **AES-256-GCM** y lo exfiltra periódicamente hacia un servidor C2 (Parrot Linux) vía TCP. El malware implementa persistencia sin privilegios de root a través del mecanismo **XDG Autostart** (archivo `.desktop` en `~/.config/autostart/`) y se camufla como `gnome-session-helper` para evadir una inspección manual básica.

---

## 2. Vector de Infección y Sistema Operativo Objetivo

### 2.1 Sistema Operativo Objetivo

- **Primario:** Ubuntu 24.04 LTS (Linux x86_64)
- **Requisito:** Sesión gráfica X11 (no Wayland) — pynput requiere X11 para hooking global de teclado
- **Requisito de privilegios:** usuario estándar (sin sudo, sin root)
- **Runtime requerido en víctima:** ninguno (binario ELF autocontenido)

### 2.2 Vectores de Infección Típicos

1. **Phishing con adjunto:** correo con binario disfrazado de documento (`reporte.pdf.sh`, instalador falso).
2. **Paquete malicioso:** distribuido como dependencia comprometida en PyPI u otro repositorio.
3. **Ingeniería social:** el atacante convence al usuario de ejecutar un "script de configuración".
4. **USB/removible:** copia automática y ejecución con autorun en entornos configurados para ello.
5. **Explotación de vulnerabilidad:** descargado y ejecutado como payload post-explotación.

---

## 3. TTPs según MITRE ATT&CK

| ID | Táctica | Técnica | Implementación en WSHLogger |
|---|---|---|---|
| T1056.001 | Credential Access | Input Capture: Keylogging | Captura vía `pynput` backend X11 (`pynput.keyboard._xorg`) |
| T1547.006 | Persistence | Boot/Logon Autostart: XDG Autostart | Archivo `~/.config/autostart/gnome-session-helper.desktop` |
| T1573.001 | Command & Control | Encrypted Channel: Symmetric Cryptography | AES-256-GCM; nonce aleatorio por chunk |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | TCP periódico con intervalo configurable |
| T1027 | Defense Evasion | Obfuscated Files or Information | Binario compilado ELF con PyInstaller + `--strip` |
| T1036.005 | Defense Evasion | Masquerading: Match Legitimate Name | Proceso `wsh`, autostart `gnome-session-helper` |
| T1560 | Collection | Archive Collected Data | Buffer local cifrado `~/.local/share/.cache_sys/session.enc` |
| T1119 | Collection | Automated Collection | Captura y envío automático sin interacción del atacante |
| T1083 | Discovery | File and Directory Discovery | Resolución de rutas del sistema (`HOME`, `.config`, `.local`) |

---

## 4. Indicadores de Compromiso (IoCs)

### 4.1 Hashes del Ejecutable

> Obtener tras compilar con PyInstaller en Ubuntu 24.04:

```bash
sha256sum dist/wsh
md5sum dist/wsh
```

| Algoritmo | Hash |
|---|---|
| SHA-256 | `<ejecutar: sha256sum dist/wsh>` |
| MD5 | `<ejecutar: md5sum dist/wsh>` |

### 4.2 Artefactos del Sistema de Archivos

| Ruta | Tipo | Descripción |
|---|---|---|
| `~/.config/autostart/gnome-session-helper.desktop` | Archivo | Mecanismo de persistencia XDG Autostart |
| `~/.local/bin/wsh` | Binario ELF | Copia del ejecutable en ruta estable del usuario |
| `~/.local/share/.cache_sys/session.enc` | Datos cifrados | Backup local de teclas capturadas (AES-256-GCM) |

### 4.3 Indicadores de Red

| Tipo | Valor | Descripción |
|---|---|---|
| Puerto destino | **TCP/4444** | Puerto C2 por defecto (configurable en código) |
| Patrón de tráfico | Conexión TCP periódica (cada 30s) hacia IP del atacante | Exfiltración cifrada regular |
| Protocolo de aplicación | 4 bytes BE (longitud) + nonce(12) + ciphertext | No es HTTP/HTTPS; tráfico binario crudo |
| Tamaño típico de paquete | 40–200 bytes por chunk (varía con el texto capturado) | Proporcional a la actividad del teclado |

### 4.4 Indicadores de Comportamiento (Runtime)

- Proceso sin ventana visible con conexiones TCP salientes periódicas al puerto 4444
- Archivo `.desktop` nuevo en `~/.config/autostart/` con `NoDisplay=true`
- Escritura periódica en `~/.local/share/.cache_sys/` (directorio oculto no estándar)
- Proceso `wsh` o `gnome-session-helper` no reconocido en lista de procesos del sistema

---

## 5. Impacto Potencial

| Categoría | Nivel | Descripción |
|---|---|---|
| **Confidencialidad** | 🔴 CRÍTICO | Captura credenciales, contraseñas, comandos sudo, mensajes privados, datos financieros |
| **Integridad** | 🟢 Bajo | No modifica archivos del sistema |
| **Disponibilidad** | 🟢 Bajo | Consumo marginal de CPU/red |
| **Cumplimiento** | 🟠 Alto | Viola GDPR, Ley 19.628 (Chile), LOPD y normativas de protección de datos |
| **Reputacional** | 🟠 Alto | Posible filtración de información corporativa o personal sensible |

### Información capturada
- Contraseñas escritas en cualquier campo de texto no protegido
- Contraseñas de `sudo` (escritas en terminal)
- Credenciales de servicios web, correo, banca en línea
- Comandos ejecutados en terminal (bash, zsh)
- Mensajes de chat, correos redactados
- Datos de formularios web en cualquier navegador

### Información NO capturada (limitaciones técnicas)
- Texto en sesiones Wayland (requiere permisos de `evdev` / root)
- Campos con SecureInput activo (KeePass, gestores de contraseñas seguros)
- Texto pegado desde el portapapeles con el ratón
- Combinaciones de sistema bloqueadas por el kernel (Ctrl+Alt+Del, Super+L)

---

## 6. Recomendaciones de Mitigación

### Para Usuarios Finales

| Medida | Descripción |
|---|---|
| **Usar Wayland** | En Ubuntu 24.04, preferir sesión Wayland en lugar de X11; pynput no puede hacer hooking global en Wayland sin root |
| **No ejecutar binarios desconocidos** | Verificar origen y firma de cualquier ejecutable antes de correrlo |
| **Revisar `~/.config/autostart/`** | Inspeccionar periódicamente archivos `.desktop` de autostart no reconocidos |
| **Gestor de contraseñas con autocompletado** | Bitwarden, 1Password → reduce teclas escritas manualmente |
| **Autenticación multifactor (MFA)** | Aunque capturen la contraseña, el segundo factor mitiga el acceso |
| **Firewall de salida (ufw)** | Bloquear conexiones TCP salientes a puertos no estándar |

### Para Especialistas TI / Blue Team

| Medida | Descripción |
|---|---|
| **Forzar sesiones Wayland** | Configurar GDM para no ofrecer sesión X11, eliminando el vector principal |
| **Monitoreo de `~/.config/autostart/`** | Auditar cambios en archivos `.desktop` con inotifywait o auditd |
| **SIEM con reglas de comportamiento** | Alertar sobre nuevos procesos sin TTY con conexiones TCP salientes periódicas |
| **Análisis de tráfico de red** | IDS (Snort/Suricata) con reglas para tráfico TCP binario en puerto 4444 |
| **AppArmor / SELinux** | Políticas que impidan a procesos de usuario acceder a la API de X11 globalmente |
| **Sandboxing de aplicaciones** | Flatpak/Snap con perfiles restrictivos limitan acceso a X11 |
| **Hunts periódicos** | Buscar archivos ELF en `~/.local/bin/` y procesos con conexiones externas sospechosas |

### Regla Auditd para detectar creación del .desktop

```bash
# Agregar a /etc/audit/audit.rules
-w /home -p wa -k autostart_watch
```

### Regla Suricata/Snort para detectar tráfico C2

```
alert tcp any any -> any 4444 (
    msg:"Posible keylogger C2 TCP/4444";
    flow:established,to_server;
    dsize:28<>10000;
    sid:9000001;
    rev:1;
)
```

---

## 7. Referencias

- MITRE ATT&CK: https://attack.mitre.org/
- XDG Autostart Specification: https://specifications.freedesktop.org/autostart-spec/
- pynput Documentation: https://pynput.readthedocs.io/
- NIST SP 800-83: Guide to Malware Incident Prevention and Handling
- FortiGuard Threat Intelligence: https://www.fortiguard.com/
- Ubuntu Security Guide: https://ubuntu.com/security
