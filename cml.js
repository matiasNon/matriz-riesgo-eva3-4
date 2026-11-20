/* RiskAndes · Importador de topologías CML (.yaml) — sin dependencias.
 * Lee nodos, enlaces, IPs y VLAN y sugiere vulnerabilidades por heurística.
 * NUNCA conserva el texto de la configuración: contraseñas, claves y PSK no salen de este módulo. */
(function (root) {
  "use strict";

  var TIPOS = {
    asav: "Firewall", iosv: "Router", csr1000v: "Router", iosxrv: "Router", iosxrv9000: "Router", "cat8000v": "Router",
    iosvl2: "Switch", "cat9000v": "Switch", nxosv: "Switch", nxosv9000: "Switch", unmanaged_switch: "Switch",
    alpine: "Host Linux", ubuntu: "Servidor Linux", server: "Servidor Linux", desktop: "Estación de trabajo",
    syslog: "Servidor de logs", external_connector: "Conexión externa", wan_emulator: "Emulador WAN"
  };
  var RED = ["Firewall", "Router", "Switch"];

  function unq(v) { v = (v || "").trim(); if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1); return v === "null" || v === "~" ? "" : v; }
  function mask2prefix(m) {
    var p = m.split(".").map(Number), bits = 0;
    for (var i = 0; i < 4; i++) { var b = p[i]; if (!(b >= 0 && b <= 255)) return null; bits += b.toString(2).replace(/0/g, "").length; }
    return bits;
  }
  function ip2int(ip) { var p = ip.split(".").map(Number); return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]; }
  function int2ip(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
  function red(ip, prefix) {
    var mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return int2ip((ip2int(ip) & mask) >>> 0) + "/" + prefix;
  }
  function esPrivada(ip) {
    var p = ip.split(".").map(Number);
    return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || p[0] === 127;
  }
  function validIp(ip) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && ip.split(".").every(function (x) { return +x <= 255; }); }

  /* ---- Lectura del YAML (formato de exportación de CML) ---- */
  function leer(texto) {
    var lines = String(texto).replace(/^﻿/, "").replace(/\r\n?/g, "\n").split("\n");
    var sec = null, nodos = [], enlaces = [], lab = {}, cur = null, mode = "plain", m;

    function key(k, v) {                       // clave de nivel 2 dentro de un nodo / enlace
      if (!cur) return;
      if (k === "interfaces") { mode = "ifaces"; return; }
      if (k === "configuration") { mode = "config"; if (v && v !== "[]") cur.cfg += v + "\n"; return; }
      mode = "plain";
      if (sec === "nodes") {
        if (k === "id") cur.id = unq(v); else if (k === "label") cur.label = unq(v);
        else if (k === "node_definition") cur.def = unq(v);
        else if (k === "x") cur.x = +unq(v) || 0; else if (k === "y") cur.y = +unq(v) || 0;
      } else if (sec === "links") {
        if (k in { n1: 1, n2: 1, i1: 1, i2: 1, label: 1, id: 1 }) cur[k] = unq(v);
      }
    }

    for (var i = 0; i < lines.length; i++) {
      var L = lines[i];
      if (!L.trim() || /^\s*#/.test(L)) { if (mode === "config" && cur) cur.cfg += L + "\n"; continue; }
      if (/^[A-Za-z_][\w-]*:/.test(L)) {       // clave de nivel 0
        var k0 = L.split(":")[0];
        sec = (k0 === "nodes" || k0 === "links" || k0 === "lab") ? k0 : null; cur = null; mode = "plain"; continue;
      }
      if (sec === "lab") {
        if ((m = /^  (title|description):\s*(.*)$/.exec(L))) lab[m[1]] = unq(m[2]);
        continue;
      }
      if (sec !== "nodes" && sec !== "links") continue;
      if ((m = /^- ([\w-]+):\s*(.*)$/.exec(L))) {   // inicia un elemento de la lista
        cur = sec === "nodes" ? { id: "", label: "", def: "", x: 0, y: 0, ifaces: [], cfg: "" } : {};
        (sec === "nodes" ? nodos : enlaces).push(cur);
        key(m[1], m[2]); continue;
      }
      if (!cur) continue;
      if ((m = /^  ([\w-]+):\s*(.*)$/.exec(L))) { key(m[1], m[2]); continue; }
      if (sec === "nodes" && mode === "ifaces") {
        if ((m = /^  - id:\s*(\S+)/.exec(L))) { cur.ifaces.push({ id: unq(m[1]), label: "" }); continue; }
        if ((m = /^    label:\s*(.*)$/.exec(L)) && cur.ifaces.length) { cur.ifaces[cur.ifaces.length - 1].label = unq(m[1]); continue; }
      }
      if (sec === "nodes" && mode === "config") cur.cfg += L + "\n";
    }
    return { nodos: nodos, enlaces: enlaces, lab: lab };
  }

  /* ---- Extracción de datos de red de la configuración (el texto se descarta después) ---- */
  function extraer(cfg) {
    var ips = [], vlans = [], hostname = "", dhcp = false, curIf = "", m, seen = {};
    function add(ip, prefix, iface) {
      if (!validIp(ip) || prefix == null || prefix < 0 || prefix > 32) return;
      var k = ip + "/" + prefix; if (seen[k]) return; seen[k] = 1;
      ips.push({ ip: ip, prefix: prefix, red: red(ip, prefix), iface: iface || "", privada: esPrivada(ip) });
    }
    cfg.split("\n").forEach(function (l) {
      if ((m = /^\s*interface\s+(\S+)/i.exec(l))) curIf = m[1];
      if ((m = /^\s*hostname:?\s+(\S+)/i.exec(l)) && !hostname) hostname = m[1];
      if ((m = /^\s*vlan\s+(\d{1,4})\s*$/i.exec(l)) && vlans.indexOf(+m[1]) < 0) vlans.push(+m[1]);
      if ((m = /\bip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i.exec(l))) add(m[1], mask2prefix(m[2]), curIf);
      else if (/\bip address\s+dhcp/i.test(l)) dhcp = true;
      if ((m = /\bip addr(?:ess)?\s+add\s+(?:dev\s+(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\/(\d+)(?:\s+dev\s+(\S+))?/i.exec(l))) add(m[2], +m[3], m[1] || m[4] || "");
      if ((m = /\baddresses:\s*\[([^\]]+)\]/i.exec(l)) && !/nameservers/i.test(l)) {
        m[1].split(",").forEach(function (a) { var c = /(\d+\.\d+\.\d+\.\d+)\/(\d+)/.exec(a); if (c) add(c[1], +c[2], curIf); });
      }
    });
    return { ips: ips, vlans: vlans.sort(function (a, b) { return a - b; }), hostname: hostname, dhcp: dhcp };
  }

  /* ---- Sugerencias de vulnerabilidad (a validar por el estudiante; no incluyen valores secretos) ---- */
  function hallazgos(tipo, cfg) {
    var h = [], tiene = cfg.trim().length > 0, esRed = RED.indexOf(tipo) >= 0;
    if (tipo === "Conexión externa") return ["Punto de entrada desde Internet: toda la exposición pasa por el perímetro"];
    if (!tiene) { h.push("Sin configuración de endurecimiento definida (valores por defecto del fabricante)"); return h; }
    if (/^\s*(enable password|username\s+\S+\s+(privilege\s+\d+\s+)?password)\b/im.test(cfg)) h.push("Contraseñas locales almacenadas en la configuración sin gestión centralizada de credenciales");
    if (/\b(USERNAME|PASSWORD)=/.test(cfg) || /^\s*password:\s*\S+/m.test(cfg)) h.push("Credenciales estáticas o predeterminadas definidas en el arranque del nodo");
    if (/ssh_pwauth:\s*true/i.test(cfg)) h.push("Autenticación SSH por contraseña habilitada (sin claves ni MFA)");
    if (/pre-shared-key/i.test(cfg)) h.push("Clave precompartida (PSK) escrita en la configuración del túnel VPN");
    if (/snmp-server community/i.test(cfg)) h.push("SNMP v1/v2c con comunidad (sin cifrado ni autenticación fuerte)");
    if (/^\s*ip http server/im.test(cfg)) h.push("Servidor HTTP de gestión habilitado (sin cifrado)");
    if (/transport input[^\n]*\b(telnet|all)\b/i.test(cfg)) h.push("Acceso remoto por Telnet permitido (texto plano)");
    if (/permit ip any any/i.test(cfg)) h.push("Regla de acceso permisiva (permit ip any any)");
    if (esRed && !/logging host|logging server/i.test(cfg)) h.push("Sin envío de registros (syslog) a un colector central");
    if (esRed && !/\baaa\b|tacacs|radius/i.test(cfg)) h.push("Sin AAA centralizado (TACACS+/RADIUS) para la administración");
    return h;
  }

  function importar(texto) {
    var d = leer(texto);
    if (!d.nodos.length) throw new Error("No se encontraron nodos. El archivo debe ser un laboratorio CML exportado en YAML.");
    var porId = {}, enlacesOut = [];
    var activos = d.nodos.map(function (n) {
      var tipo = TIPOS[n.def] || (n.def ? n.def : "Dispositivo");
      var ex = extraer(n.cfg);
      var a = {
        id: n.label || n.id, nombre: n.label || n.id, tipo: tipo, def: n.def, hostname: ex.hostname,
        ips: ex.ips.map(function (x) { return x.ip + "/" + x.prefix; }), redes: [], vlans: ex.vlans, dhcp: ex.dhcp,
        publica: ex.ips.some(function (x) { return !x.privada; }),
        ifaces: n.ifaces.length, conexiones: [], criticidad: criticidadSugerida(tipo, n.label || n.id), ubicacion: "On-premise",
        destino: destinoSugerido(tipo), vulns: hallazgos(tipo, n.cfg), riesgos: [], notas: "", origen: "cml", x: n.x, y: n.y
      };
      ex.ips.forEach(function (x) { if (a.redes.indexOf(x.red) < 0) a.redes.push(x.red); });
      porId[n.id] = a; return a;
    });
    d.enlaces.forEach(function (e) {
      var a = porId[e.n1], b = porId[e.n2]; if (!a || !b) return;
      var ia = ifLabel(d.nodos, e.n1, e.i1), ib = ifLabel(d.nodos, e.n2, e.i2);
      a.conexiones.push(b.nombre + (ia || ib ? " (" + ia + " ↔ " + ib + ")" : ""));
      b.conexiones.push(a.nombre + (ia || ib ? " (" + ib + " ↔ " + ia + ")" : ""));
      enlacesOut.push({ a: a.id, b: b.id, ia: ia, ib: ib });
    });
    var redes = {}; activos.forEach(function (a) { a.redes.forEach(function (r) { redes[r] = 1; }); });
    return { titulo: d.lab.title || "", descripcion: d.lab.description || "", activos: activos, enlaces: enlacesOut, redes: Object.keys(redes) };
  }
  function ifLabel(nodos, nid, iid) {
    for (var i = 0; i < nodos.length; i++) if (nodos[i].id === nid) {
      for (var j = 0; j < nodos[i].ifaces.length; j++) if (nodos[i].ifaces[j].id === iid) return nodos[i].ifaces[j].label;
    }
    return "";
  }
  /* Criticidad inicial por rol (1–5): es una sugerencia, el estudiante la ajusta en el inventario. */
  function criticidadSugerida(tipo, nombre) {
    if (tipo === "Conexión externa") return 1;
    if (/dato|db|sql|base/i.test(nombre)) return 5;
    if (/siem|tacacs|aaa|plc|hmi|scada|ids/i.test(nombre)) return 4;
    if (tipo === "Firewall" || tipo === "Switch") return 4;
    if (/casa|remot|tecnico/i.test(nombre)) return 2;
    return 3;
  }
  function destinoSugerido(tipo) {
    if (RED.indexOf(tipo) >= 0) return "Reemplazar por servicio nativo de la nube";
    if (tipo === "Conexión externa") return "No aplica";
    return "Migrar a instancia en la nube";
  }

  var api = { importar: importar, leer: leer, extraer: extraer, hallazgos: hallazgos, red: red, esPrivada: esPrivada, mask2prefix: mask2prefix, TIPOS: TIPOS };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.CML = api;
})(typeof window !== "undefined" ? window : globalThis);
