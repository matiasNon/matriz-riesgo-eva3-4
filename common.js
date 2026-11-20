/* RiskAndes · módulo común (cálculo de riesgo, almacenamiento, interfaz, XLSX). Sin dependencias. */
(function (root) {
"use strict";
/* ============ Modelo de cálculo (R = P × I) ============ */
function nivelDe(r){
  if (r >= 17) return {k:"critico", nombre:"Crítico", accion:"Intervenir ya"};
  if (r >= 10) return {k:"alto",    nombre:"Alto",    accion:"Intervenir pronto"};
  if (r >= 6)  return {k:"medio",   nombre:"Medio",   accion:"Mejorar controles"};
  return            {k:"bajo",    nombre:"Bajo",    accion:"Monitorear"};
}
function calc(p, i){ var r = p * i; return {r:r, n:nivelDe(r)}; }

var ISO = {
  "A.5.15":"Control de acceso","A.5.16":"Gestión de identidad","A.5.17":"Información de autenticación",
  "A.5.28":"Recopilación de evidencia","A.5.30":"Preparación TIC para la continuidad","A.5.34":"Privacidad y protección de datos personales",
  "A.6.3":"Concienciación y capacitación","A.7.1":"Perímetros de seguridad física","A.7.2":"Entrada física","A.7.4":"Monitoreo de seguridad física",
  "A.8.2":"Derechos de acceso privilegiado","A.8.3":"Restricción de acceso a la información","A.8.4":"Acceso al código fuente",
  "A.8.5":"Autenticación segura","A.8.6":"Gestión de la capacidad","A.8.7":"Protección contra malware","A.8.8":"Gestión de vulnerabilidades técnicas",
  "A.8.13":"Respaldo de la información","A.8.14":"Redundancia","A.8.15":"Registro (logging)","A.8.16":"Actividades de monitoreo",
  "A.8.20":"Seguridad de redes","A.8.22":"Segregación de redes","A.8.24":"Uso de criptografía"
};


/* Caso CoopAndes Digital: 6 hallazgos con justificación (escala de la Guía Didáctica) */
var CASO = [
  {id:"R-01", activo:"Bucket S3 de respaldos", amenaza:"Fuga de datos de respaldos por acceso público no autorizado", vulnerabilidad:"Bucket con acceso público de lectura",
   p:5, i:4, fuente:"P=5: buckets públicos son escaneados de forma activa en Internet (Guía Didáctica, nivel 5: intentos activos). I=4: respaldos con datos financieros de la cooperativa (nivel 4). Evidencia: hallazgo del caso; verificable con AWS Config (s3-bucket-public-read-prohibited).",
   control:"Activar S3 Block Public Access a nivel de cuenta, política de mínimo privilegio, cifrado SSE-KMS y versionado.", iso:"A.5.15, A.8.3, A.8.24", pr:1, ir:3},
  {id:"R-02", activo:"Security Group de servidores", amenaza:"Fuerza bruta y acceso remoto no autorizado a servidores", vulnerabilidad:"SSH (22) y RDP (3389) abiertos a 0.0.0.0/0",
   p:5, i:4, fuente:"P=5: puertos 22/3389 expuestos reciben intentos de autenticación automatizados continuos (nivel 5). I=4: acceso a sistemas críticos. Evidencia: hallazgo del caso; verificable con Security Group y AWS Trusted Advisor.",
   control:"Cerrar 22/3389 a Internet; acceso por VPN o Session Manager con MFA y rangos IP permitidos.", iso:"A.8.20, A.8.22, A.8.5", pr:1, ir:4},
  {id:"R-03", activo:"Cuenta root de la nube", amenaza:"Toma de control total de la cuenta por credencial comprometida", vulnerabilidad:"Sin MFA y usada por tres personas (sin trazabilidad individual)",
   p:3, i:5, fuente:"P=3: vulnerabilidad conocida (sin MFA, credencial compartida) pero sin intentos activos documentados (nivel 3). I=5: root controla toda la operación y datos; paralización o violación legal (nivel 5). Evidencia: hallazgo del caso; verificable con IAM Credential Report.",
   control:"MFA con llave física en root, usuarios nominales por IAM Identity Center, no usar root a diario y alarma ante su uso.", iso:"A.5.16, A.5.17, A.8.2, A.8.5", pr:1, ir:5},
  {id:"R-04", activo:"Base de datos del portal", amenaza:"Exfiltración de datos personales y financieros de socios", vulnerabilidad:"IP pública y almacenamiento sin cifrar",
   p:4, i:5, fuente:"P=4: base con IP pública es objetivo de intentos documentados (nivel 4). I=5: datos personales y financieros de miles de socios con exposición legal (Ley 19.628) (nivel 5). Evidencia: hallazgo del caso; verificable en la configuración de la instancia de base de datos.",
   control:"Mover a subred privada sin IP pública, cifrado en reposo (KMS) y TLS obligatorio, acceso solo desde la aplicación.", iso:"A.8.24, A.8.20, A.5.34", pr:1, ir:4},
  {id:"R-05", activo:"Plataforma en la nube (auditoría)", amenaza:"Incidente no detectado y sin evidencia forense", vulnerabilidad:"Ausencia de registro de actividad en la nube",
   p:3, i:4, fuente:"P=3: sin registro no se detectan incidentes ni se reconstruyen (nivel 3). I=4: sin trazabilidad no se puede acotar ni demostrar el alcance de un incidente en sistemas críticos (nivel 4). Evidencia: hallazgo del caso; verificable en la consola del proveedor.",
   control:"Trail multi-región con validación de integridad, bucket inmutable (Object Lock) y alertas de actividad anómala.", iso:"A.8.15, A.8.16, A.5.28", pr:2, ir:2},
  {id:"R-06", activo:"Rack on premise y respaldos", amenaza:"Acceso físico no autorizado y pérdida irrecuperable de datos", vulnerabilidad:"Rack sin control de acceso y respaldos sin pruebas de restauración",
   p:3, i:4, fuente:"P=3: vulnerabilidades conocidas sin intentos documentados (nivel 3). I=4: afecta sistemas críticos y la capacidad de recuperación (nivel 4). Evidencia: hallazgo del caso; verificable con inspección física y bitácora de respaldos.",
   control:"Cerradura con registro de acceso, CCTV y bitácora; respaldos 3-2-1 con pruebas de restauración trimestrales.", iso:"A.7.1, A.7.2, A.7.4, A.8.13, A.5.30", pr:2, ir:3}
];


/* ================= RiskAndes · módulo común ================= */
var RA = { nivelDe: nivelDe, calc: calc, ISO: ISO, CASO: CASO };
var extra = {
  "A.5.1": "Políticas de seguridad de la información", "A.5.23": "Seguridad de la información en el uso de servicios en la nube",
  "A.5.24": "Planificación y preparación de la gestión de incidentes", "A.5.29": "Seguridad de la información durante una interrupción",
  "A.8.9": "Gestión de la configuración", "A.8.12": "Prevención de fuga de datos", "A.8.32": "Gestión de cambios"
};
Object.keys(extra).forEach(function (k) { ISO[k] = extra[k]; });

RA.KEYS = { riesgos: "riskandes.v1", inv: "riskandes.inv", mig: "riskandes.mig", cont: "riskandes.cont", sgsi: "riskandes.sgsi", nube: "riskandes.nube", meta: "riskandes.meta" };
RA.META_DEF = { org: "CoopAndes Digital", titulo: "Plan de migración a la nube y matriz de riesgos", grupo: "", integrantes: "", docente: "Daniel Ruz Moreno", asignatura: "Diseño de Arquitectura de Redes Seguras" };
RA.INV_DEF = { titulo: "", descripcion: "", activos: [], enlaces: [], origen: "manual" };
RA.NUBE_DEF = { proveedor: "", region: "", zonas: [], instancias: [], reglas: [] };

var mem = {};
RA.clone = function (v) { return JSON.parse(JSON.stringify(v)); };
RA.load = function (key, def) {
  if (key in mem) return mem[key];
  var v = null;
  try { var s = localStorage.getItem(key); if (s) v = JSON.parse(s); } catch (e) { v = null; }
  if (v === null || (Array.isArray(def) && !Array.isArray(v))) v = RA.clone(def);
  mem[key] = v; return v;
};
RA.save = function (key, val) { mem[key] = val; try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} };
RA.riesgos = function () { return RA.load(RA.KEYS.riesgos, CASO); };
RA.res = function (x) { return x.pr && x.ir ? calc(x.pr, x.ir) : calc(x.p, x.i); };
RA.esc = function (s) { return String(s == null ? "" : s); };

/* ---- CSV ---- */
RA.csvCell = function (v) {
  v = String(v == null ? "" : v);
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;      // evita inyección de fórmulas al abrir en Excel
  return '"' + v.replace(/"/g, '""') + '"';
};
RA.csv = function (rows) { return "﻿" + rows.map(function (r) { return r.map(RA.csvCell).join(","); }).join("\r\n"); };

/* ---- XLSX mínimo (ZIP sin compresión + SpreadsheetML), sin librerías ---- */
var CRC = (function () { var t = [], c, n, k; for (n = 0; n < 256; n++) { c = n; for (k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(b) { var c = 0xFFFFFFFF; for (var i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function utf8(s) { return new TextEncoder().encode(s); }
function zip(files) {
  var parts = [], central = [], offset = 0;
  files.forEach(function (f) {
    var nb = utf8(f.name), crc = crc32(f.data), size = f.data.length;
    var lh = new Uint8Array(30 + nb.length), v = new DataView(lh.buffer);
    v.setUint32(0, 0x04034b50, true); v.setUint16(4, 20, true); v.setUint16(6, 0x0800, true); v.setUint16(8, 0, true);
    v.setUint16(10, 0, true); v.setUint16(12, 0x21, true); v.setUint32(14, crc, true); v.setUint32(18, size, true); v.setUint32(22, size, true);
    v.setUint16(26, nb.length, true); v.setUint16(28, 0, true); lh.set(nb, 30);
    var ch = new Uint8Array(46 + nb.length), c = new DataView(ch.buffer);
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true);
    c.setUint16(12, 0, true); c.setUint16(14, 0x21, true); c.setUint32(16, crc, true); c.setUint32(20, size, true); c.setUint32(24, size, true);
    c.setUint16(28, nb.length, true); c.setUint32(42, offset, true); ch.set(nb, 46);
    parts.push(lh, f.data); central.push(ch); offset += lh.length + size;
  });
  var cdSize = central.reduce(function (a, b) { return a + b.length; }, 0), end = new Uint8Array(22), e = new DataView(end.buffer);
  e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true); e.setUint32(12, cdSize, true); e.setUint32(16, offset, true);
  var all = parts.concat(central, [end]), total = all.reduce(function (a, b) { return a + b.length; }, 0), out = new Uint8Array(total), p = 0;
  all.forEach(function (b) { out.set(b, p); p += b.length; });
  return out;
}
function xml(s) { return String(s == null ? "" : s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function colName(n) { var s = ""; n++; while (n > 0) { var m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); } return s; }
function sheetXml(rows) {
  var widths = [];
  rows.forEach(function (r) { r.forEach(function (c, i) { widths[i] = Math.min(60, Math.max(widths[i] || 8, String(c == null ? "" : c).split("\n")[0].length + 2)); }); });
  var x = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">';
  if (widths.length) x += "<cols>" + widths.map(function (w, i) { return '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + w + '" customWidth="1"/>'; }).join("") + "</cols>";
  x += "<sheetData>";
  rows.forEach(function (r, ri) {
    x += '<row r="' + (ri + 1) + '">';
    r.forEach(function (c, ci) {
      var ref = colName(ci) + (ri + 1), st = ri === 0 ? 1 : 2;
      if (typeof c === "number" && isFinite(c)) x += '<c r="' + ref + '" s="' + st + '"><v>' + c + "</v></c>";
      else x += '<c r="' + ref + '" t="inlineStr" s="' + st + '"><is><t xml:space="preserve">' + xml(c) + "</t></is></c>";
    });
    x += "</row>";
  });
  return x + "</sheetData></worksheet>";
}
RA.xlsx = function (sheets) {
  var NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main", used = {};
  var names = sheets.map(function (s, i) {
    var n = String(s.name || "Hoja" + (i + 1)).replace(/[\[\]:*?\/\\]/g, " ").trim().slice(0, 31) || "Hoja" + (i + 1), b = n, k = 2;
    while (used[n.toLowerCase()]) n = b.slice(0, 28) + " " + k++;
    used[n.toLowerCase()] = 1; return n;
  });
  var files = [];
  files.push({ name: "[Content_Types].xml", data: utf8('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' + sheets.map(function (s, i) { return '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'; }).join("") + "</Types>") });
  files.push({ name: "_rels/.rels", data: utf8('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>') });
  files.push({ name: "xl/workbook.xml", data: utf8('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="' + NS + '" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + names.map(function (n, i) { return '<sheet name="' + xml(n) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>'; }).join("") + "</sheets></workbook>") });
  files.push({ name: "xl/_rels/workbook.xml.rels", data: utf8('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + sheets.map(function (s, i) { return '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>'; }).join("") + '<Relationship Id="rId' + (sheets.length + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>') });
  files.push({ name: "xl/styles.xml", data: utf8('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="' + NS + '"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>') });
  sheets.forEach(function (s, i) { files.push({ name: "xl/worksheets/sheet" + (i + 1) + ".xml", data: utf8(sheetXml(s.rows)) }); });
  return zip(files);
};

/* ---- Proyecto completo (respaldo/restauración en JSON) ---- */
RA.exportProyecto = function () {
  var o = { app: "RiskAndes", version: 2 };
  Object.keys(RA.KEYS).forEach(function (k) { o[k] = RA.load(RA.KEYS[k], k === "meta" ? RA.META_DEF : k === "inv" ? RA.INV_DEF : k === "nube" ? RA.NUBE_DEF : k === "riesgos" ? CASO : []); });
  return o;
};
RA.importProyecto = function (o) {
  if (!o || o.app !== "RiskAndes") throw new Error("El archivo no es un proyecto RiskAndes.");
  var arr = ["riesgos", "mig", "cont", "sgsi"], obj = ["inv", "nube", "meta"];
  arr.forEach(function (k) { if (k in o && !Array.isArray(o[k])) throw new Error("Formato inválido en «" + k + "»."); });
  obj.forEach(function (k) { if (k in o && (typeof o[k] !== "object" || Array.isArray(o[k]) || !o[k])) throw new Error("Formato inválido en «" + k + "»."); });
  arr.concat(obj).forEach(function (k) { if (k in o) RA.save(RA.KEYS[k], o[k]); });
};

if (typeof document === "undefined") { root.RA = RA; if (typeof module !== "undefined" && module.exports) module.exports = RA; return; }

/* ============== Utilidades de interfaz (solo navegador) ============== */
function $(id) { return document.getElementById(id); }
function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt !== undefined) e.textContent = txt; return e; }
RA.$ = $; RA.el = el;
RA.chip = function (n, r) { return el("span", "chip " + n.k, n.nombre + " · " + r); };
RA.download = function (name, data, type) {
  var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([data], { type: type })); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
};
RA.hoy = function () { return new Date().toLocaleDateString("es-CL"); };

RA.tema = function () {
  try { var t = localStorage.getItem("riskandes.tema"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) {}
};
RA.toggleTema = function () {
  var r = document.documentElement, oscuro = r.getAttribute("data-theme") === "dark" || (!r.getAttribute("data-theme") && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  var t = oscuro ? "light" : "dark"; r.setAttribute("data-theme", t); try { localStorage.setItem("riskandes.tema", t); } catch (e) {}
};

RA.PAGINAS = [["index.html", "Matriz de riesgos"], ["inventario.html", "Inventario"], ["migracion.html", "Migración"], ["nube.html", "Nube"], ["informe.html", "Informe"]];
RA.header = function (activa, acciones) {
  RA.tema();
  var h = $("top"); h.className = "top"; h.textContent = "";
  var b = el("div", "brand");
  b.innerHTML = '<svg viewBox="0 0 48 48" role="img" aria-label="Logotipo RiskAndes"><rect width="48" height="48" rx="10" fill="#1f5fbf"/><path d="M4 38 L17 16 L24 27 L30 19 L44 38 Z" fill="#ffffff" opacity=".95"/><path d="M17 16 L20 21 L14 21 Z" fill="#d93636"/><circle cx="35" cy="12" r="4" fill="#f2c230"/></svg>';
  var t = el("div"); t.appendChild(el("h1", "", "RiskAndes")); t.appendChild(el("p", "", "Matriz de riesgos y migración a la nube")); b.appendChild(t); h.appendChild(b);
  var nav = el("nav", "nav"); nav.setAttribute("aria-label", "Secciones");
  RA.PAGINAS.forEach(function (p) { var a = el("a", "", p[1]); a.href = p[0]; if (p[0] === activa) a.setAttribute("aria-current", "page"); nav.appendChild(a); });
  h.appendChild(nav);
  var ac = el("div", "actions");
  (acciones || []).concat([{ label: "Tema", fn: RA.toggleTema, aria: "Cambiar tema claro u oscuro" }]).forEach(function (x) {
    var bt = el("button", x.cls || "", x.label); bt.type = "button"; if (x.id) bt.id = x.id; if (x.aria) bt.setAttribute("aria-label", x.aria); bt.addEventListener("click", x.fn); ac.appendChild(bt);
  });
  h.appendChild(ac); return ac;
};

/* ---- Matriz de calor 5×5 ---- */
RA.heat = function (cont, risks, modo) {
  cont.textContent = "";
  var mapa = {};
  risks.forEach(function (x) {
    var p = modo === "inh" ? x.p : (x.pr || x.p), i = modo === "inh" ? x.i : (x.ir || x.i), k = p + "-" + i; (mapa[k] = mapa[k] || []).push(x.id);
  });
  for (var p = 5; p >= 1; p--) {
    cont.appendChild(el("div", "ax", String(p)));
    for (var i = 1; i <= 5; i++) {
      var r = p * i, n = nivelDe(r), c = el("div", "hc " + n.k);
      c.title = "P=" + p + ", I=" + i + ", R=" + r + " (" + n.nombre + ")";
      (mapa[p + "-" + i] || []).forEach(function (id) { c.appendChild(el("span", "pill", id)); });
      c.appendChild(el("small", "", String(r))); cont.appendChild(c);
    }
  }
  cont.appendChild(el("div", "ax", ""));
  for (var j = 1; j <= 5; j++) cont.appendChild(el("div", "ax", "I = " + j));
};

/* ---- Tabla genérica: cols = [{h, f(row, i) -> texto | Node | [Node]}] ---- */
RA.table = function (cols, rows, vacio) {
  var w = el("div", "tablewrap"), t = el("table"), th = el("thead"), tr = el("tr");
  cols.forEach(function (c) { var h = el("th", c.cls || "", c.h); tr.appendChild(h); }); th.appendChild(tr); t.appendChild(th);
  var tb = el("tbody");
  if (!rows.length) { var r0 = el("tr"), td = el("td", "empty", vacio || "Sin registros."); td.colSpan = cols.length; r0.appendChild(td); tb.appendChild(r0); }
  rows.forEach(function (row, idx) {
    var r = el("tr");
    cols.forEach(function (c) {
      var td = el("td", c.cls || ""), v = c.f(row, idx);
      if (Array.isArray(v)) v.forEach(function (n) { td.appendChild(n); });
      else if (v && v.nodeType) td.appendChild(v); else td.textContent = v == null ? "" : String(v);
      r.appendChild(td);
    });
    tb.appendChild(r);
  });
  t.appendChild(tb); w.appendChild(t); return w;
};

/* ---- CRUD genérico: formulario + tabla con editar/borrar ----
 * o = {mount, fields:[{k,label,type,options,req,placeholder,maxlength}], cols?, get, set, prefix, onChange, vacio, agregar, rowActions(row)->[{label,fn}]} */
RA.crud = function (o) {
  var root = el("div"), bar = el("div", "crudbar"), form = el("form", "crud-form"), tabla = el("div"), msg = el("div", "msg"), editando = null, inputs = {};
  form.hidden = true; form.noValidate = true; o.mount.appendChild(root);
  var add = el("button", "primary small", o.agregar || "＋ Agregar"); add.type = "button"; bar.appendChild(add);
  root.appendChild(bar); root.appendChild(form); root.appendChild(tabla);

  function opts(f) { var v = typeof f.options === "function" ? f.options() : (f.options || []); return v.map(function (x) { return typeof x === "object" ? x : { v: x, l: x }; }); }
  function construir() {
    form.textContent = "";
    var grid = el("div", "crud-grid"); inputs = {};
    o.fields.forEach(function (f) {
      var box = el("div", "f-" + (f.type || "text")), lab = el("label", f.req ? "req" : "", f.label), ctl;
      var uid = "c" + Math.random().toString(36).slice(2, 8); lab.setAttribute("for", uid);
      if (f.type === "textarea") { ctl = el("textarea"); }
      else if (f.type === "select") { ctl = el("select"); opts(f).forEach(function (x) { var op = el("option", "", x.l); op.value = x.v; ctl.appendChild(op); }); }
      else if (f.type === "checks") {
        ctl = el("div", "checks"); lab.removeAttribute("for"); ctl.id = uid;
        var os = opts(f); if (!os.length) ctl.appendChild(el("span", "note", f.vacio || "Sin opciones disponibles."));
        os.forEach(function (x) { var l = el("label", "chk"), c = el("input"); c.type = "checkbox"; c.value = x.v; l.appendChild(c); l.appendChild(document.createTextNode(" " + x.l)); ctl.appendChild(l); });
      } else { ctl = el("input"); ctl.type = f.type || "text"; }
      if (f.placeholder) ctl.placeholder = f.placeholder;
      if (f.type !== "checks") { ctl.id = uid; if (f.maxlength || !f.type || f.type === "text" || f.type === "textarea") ctl.maxLength = f.maxlength || 400; }
      if (f.type === "number") { ctl.min = f.min != null ? f.min : 0; if (f.max != null) ctl.max = f.max; }
      inputs[f.k] = ctl; box.appendChild(lab); box.appendChild(ctl); grid.appendChild(box);
    });
    form.appendChild(grid); form.appendChild(msg);
    var ok = el("button", "primary", "Guardar"); ok.type = "submit"; var cx = el("button", "", "Cancelar"); cx.type = "button"; cx.addEventListener("click", cerrar);
    form.appendChild(ok); form.appendChild(document.createTextNode(" ")); form.appendChild(cx);
  }
  function setVal(f, v) {
    var c = inputs[f.k];
    if (f.toForm) v = f.toForm(v);
    if (f.type === "checks") Array.prototype.forEach.call(c.querySelectorAll("input"), function (i) { i.checked = (v || []).indexOf(i.value) >= 0; });
    else { c.value = v == null ? "" : v; if (f.type === "select" && c.selectedIndex < 0) c.selectedIndex = 0; }
  }
  function getVal(f) {
    var c = inputs[f.k], v;
    if (f.type === "checks") v = Array.prototype.filter.call(c.querySelectorAll("input"), function (i) { return i.checked; }).map(function (i) { return i.value; });
    else if (f.type === "number") v = c.value === "" ? "" : Number(c.value);
    else v = c.value.trim();
    return f.fromForm ? f.fromForm(v) : v;
  }
  function abrir(row) {
    construir(); editando = row ? row.id : null; msg.textContent = "";
    o.fields.forEach(function (f) { setVal(f, row ? row[f.k] : (f.def !== undefined ? f.def : "")); });
    form.hidden = false; var p = form.querySelector("input,select,textarea"); if (p && p.focus) p.focus();
  }
  function cerrar() { form.hidden = true; editando = null; }
  function siguienteId(lista) {
    var n = 0; lista.forEach(function (r) { var m = new RegExp("^" + o.prefix + "-(\\d+)$").exec(r.id || ""); if (m) n = Math.max(n, +m[1]); });
    return o.prefix + "-" + String(n + 1).padStart(2, "0");
  }
  add.addEventListener("click", function () { abrir(null); });
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var lista = o.get(), row = {};
    for (var i = 0; i < o.fields.length; i++) {
      var f = o.fields[i], v = getVal(f); row[f.k] = v;
      if (f.req && (v === "" || (Array.isArray(v) && !v.length))) { msg.textContent = "Completa el campo obligatorio: " + f.label + "."; return; }
    }
    if (o.validar) { var e = o.validar(row, lista, editando); if (e) { msg.textContent = e; return; } }
    if (editando) { lista = lista.map(function (r) { return r.id === editando ? Object.assign({}, r, row, { id: editando }) : r; }); }
    else { row.id = siguienteId(lista); lista = lista.concat([row]); }
    o.set(lista); cerrar(); dibujar(); if (o.onChange) o.onChange();
  });
  function dibujar() {
    var lista = o.get();
    var cols = (o.cols || o.fields.map(function (f) { return { h: f.label, f: function (r) { var v = r[f.k]; return Array.isArray(v) ? v.join(", ") : v; } }; })).slice();
    cols.push({ h: "Acciones", cls: "noprint", f: function (r) {
      var out = [], mk = function (txt, cls, fn) { var b = el("button", "small " + cls, txt); b.type = "button"; b.style.marginRight = "4px"; b.addEventListener("click", fn); out.push(b); };
      mk("Editar", "", function () { abrir(r); });
      mk("Borrar", "danger", function () { if (!window.confirm("¿Borrar " + r.id + "?")) return; o.set(o.get().filter(function (x) { return x.id !== r.id; })); dibujar(); if (o.onChange) o.onChange(); });
      (o.rowActions ? o.rowActions(r) : []).forEach(function (a) { mk(a.label, a.cls || "", a.fn); });
      return out;
    } });
    tabla.textContent = ""; tabla.appendChild(RA.table(cols, lista, o.vacio));
  }
  dibujar();
  return { render: dibujar, abrir: abrir, toolbar: bar };
};

/* ---- Diagrama de topología (a partir de x,y de CML y los enlaces) ---- */
RA.topoSvg = function (inv) {
  var A = (inv.activos || []).filter(function (a) { return typeof a.x === "number"; });
  if (!A.length) return null;
  var NS = "http://www.w3.org/2000/svg", byId = {}; A.forEach(function (a) { byId[a.id] = a; });
  var xs = A.map(function (a) { return a.x; }), ys = A.map(function (a) { return a.y; });
  var x0 = Math.min.apply(null, xs) - 90, x1 = Math.max.apply(null, xs) + 90, y0 = Math.min.apply(null, ys) - 40, y1 = Math.max.apply(null, ys) + 40;
  var svg = document.createElementNS(NS, "svg"); svg.setAttribute("viewBox", [x0, y0, x1 - x0, y1 - y0].join(" ")); svg.setAttribute("class", "topo");
  svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Diagrama de la topología de red importada");
  function mk(tag, attrs, txt) { var e = document.createElementNS(NS, tag); Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); }); if (txt) e.textContent = txt; return e; }
  (inv.enlaces || []).forEach(function (l) {
    var a = byId[l.a], b = byId[l.b]; if (a && b) svg.appendChild(mk("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "tl" }));
  });
  var cls = { "Firewall": "fw", "Router": "rt", "Switch": "sw", "Conexión externa": "ext" };
  A.forEach(function (a) {
    var w = Math.max(76, a.nombre.length * 7.4 + 18), g = mk("g", { class: "tn t-" + (cls[a.tipo] || "host") });
    g.appendChild(mk("title", {}, a.nombre + " · " + a.tipo + (a.ips && a.ips.length ? " · " + a.ips.join(", ") : "")));
    g.appendChild(mk("rect", { x: a.x - w / 2, y: a.y - 14, width: w, height: 28, rx: 7 }));
    g.appendChild(mk("text", { x: a.x, y: a.y + 4, "text-anchor": "middle" }, a.nombre)); svg.appendChild(g);
  });
  return svg;
};

root.RA = RA;
})(typeof window !== "undefined" ? window : globalThis);
