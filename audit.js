/* RiskAndes · Auditor de configuración en la nube y generador de propuestas. Sin dependencias. */
(function (root) {
  "use strict";

  var PUERTOS_ADMIN = { 22: "SSH", 3389: "RDP", 23: "Telnet", 5900: "VNC" };
  var PUERTOS_DATOS = { 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 445: "SMB", 9200: "Elasticsearch" };
  var SEV_ORDEN = { critico: 0, alto: 1, medio: 2, info: 3 };

  function esInternet(o) { return /^\s*(0\.0\.0\.0\/0|::\/0|any|internet|\*|todo|todos)\s*$/i.test(o || ""); }
  function todosPuertos(spec) { return /^\s*(any|\*|todos?|all|)\s*$/i.test(spec || ""); }

  /* ¿la especificación de puertos ("22", "80,443", "1000-2000", "any") incluye el puerto p? */
  function puertoIncluye(spec, p) {
    if (todosPuertos(spec)) return true;
    return String(spec).split(",").some(function (t) {
      var m = /^\s*(\d+)\s*-\s*(\d+)\s*$/.exec(t);
      if (m) return p >= +m[1] && p <= +m[2];
      return +t === p;
    });
  }
  function puertosEn(spec, tabla) {
    return Object.keys(tabla).map(Number).filter(function (p) { return puertoIncluye(spec, p); });
  }

  function auditar(nube) {
    var zonas = nube.zonas || [], inst = nube.instancias || [], reglas = nube.reglas || [], out = [];
    var zonaPorId = {}; zonas.forEach(function (z) { zonaPorId[z.id] = z; });
    function f(sev, regla, detalle, iso, rec, ref) { out.push({ sev: sev, regla: regla, detalle: detalle, iso: iso, rec: rec, ref: ref || "" }); }
    function tipoZona(ref) { var z = zonaPorId[ref]; return z ? z.tipo : ""; }

    reglas.forEach(function (r) {
      if (r.accion !== "permitir") return;
      var id = r.id + " · " + r.nombre, inet = esInternet(r.origen), tcpudp = r.proto === "tcp" || r.proto === "udp" || r.proto === "any";
      if (inet && r.proto === "any" && todosPuertos(r.puerto))
        f("critico", "Regla permite todo el tráfico desde Internet", id + ": cualquier protocolo y puerto desde cualquier origen.", "A.8.20, A.8.22", "Eliminar la regla y abrir solo los puertos de servicio necesarios.", r.id);
      else if (inet && tcpudp) {
        var adm = puertosEn(r.puerto, PUERTOS_ADMIN);
        if (adm.length && !todosPuertos(r.puerto))
          f("critico", "Administración remota abierta a Internet", id + ": " + adm.map(function (p) { return PUERTOS_ADMIN[p] + " (" + p + ")"; }).join(", ") + " desde 0.0.0.0/0.", "A.8.20, A.8.5", "Restringir a la IP de la VPN/bastión o usar un servicio de acceso sin puertos abiertos, con MFA.", r.id);
        else if (adm.length && todosPuertos(r.puerto))
          f("critico", "Todos los puertos (incluida la administración) abiertos a Internet", id + ": rango completo desde 0.0.0.0/0.", "A.8.20, A.8.5", "Limitar a los puertos de servicio necesarios.", r.id);
        var dat = todosPuertos(r.puerto) ? [] : puertosEn(r.puerto, PUERTOS_DATOS);
        if (dat.length)
          f("critico", "Servicio de datos expuesto a Internet", id + ": " + dat.map(function (p) { return PUERTOS_DATOS[p] + " (" + p + ")"; }).join(", ") + ".", "A.8.20, A.8.24", "Cerrar el acceso público; permitir solo desde la zona de aplicación.", r.id);
        if (puertoIncluye(r.puerto, 80) && !todosPuertos(r.puerto))
          f("medio", "HTTP sin cifrado expuesto", id + ": el puerto 80 acepta tráfico de Internet.", "A.8.24", "Redirigir a HTTPS (443) y usar TLS moderno.", r.id);
      }
      if (inet && tipoZona(r.destino) === "datos" && !out.some(function (x) { return x.ref === r.id && x.sev === "critico"; }))
        f("alto", "Acceso de Internet directo a la zona de datos", id + ": destino " + r.destino + " (zona de datos).", "A.8.22", "Pasar por la capa de aplicación; la zona de datos no debe recibir tráfico de Internet.", r.id);
      if (tipoZona(r.origen) === "publica" && tipoZona(r.destino) === "datos")
        f("alto", "Sin segmentación por capas (pública → datos)", id + ": la zona pública llega directo a la de datos.", "A.8.22", "Intercalar una zona de aplicación y permitir solo los puertos requeridos.", r.id);
      if (r.dir === "salida" && esInternet(r.destino) && todosPuertos(r.puerto) && tipoZona(r.origen) === "datos")
        f("medio", "Salida irrestricta desde la zona de datos", id + ": la zona de datos puede conectarse a cualquier destino.", "A.8.20, A.8.12", "Limitar la salida a actualizaciones y destinos necesarios (evita exfiltración).", r.id);
    });

    inst.forEach(function (i) {
      var z = zonaPorId[i.zona];
      if (!z) f("medio", "Instancia sin zona válida", i.nombre + ": no está asociada a una zona existente.", "A.8.22", "Asignar la instancia a una zona (subred).", i.id);
      else if (i.publica && (z.tipo === "datos" || z.tipo === "privada" || z.tipo === "gestion"))
        f("alto", "IP pública en zona " + z.tipo, i.nombre + " (" + z.nombre + ") tiene IP pública.", "A.8.20, A.8.22", "Quitar la IP pública; publicar el servicio mediante balanceador/WAF o acceder por VPN.", i.id);
    });

    if (reglas.length && !reglas.some(function (r) { return r.accion === "denegar" && esInternet(r.origen) && todosPuertos(r.puerto) && r.proto === "any"; }))
      f("info", "Sin regla explícita de denegación por defecto", "Documentar que lo no permitido queda denegado (los grupos de seguridad de la nube lo hacen por defecto).", "A.8.20", "Agregar una regla final 'denegar todo' o dejar constancia del comportamiento por defecto.");
    if (!zonas.length) f("info", "Sin zonas definidas", "No se ha segmentado la red en la nube.", "A.8.22", "Definir al menos zonas de aplicación, datos y administración.");

    out.sort(function (a, b) { return SEV_ORDEN[a.sev] - SEV_ORDEN[b.sev]; });
    return out;
  }

  /* ---- Propuestas automáticas desde el inventario ---- */
  function tipoZonaDe(red, activos) {
    var miembros = activos.filter(function (a) { return a.redes && a.redes.indexOf(red) >= 0; });
    var n = miembros.map(function (a) { return (a.nombre + " " + (a.tipo || "")).toLowerCase(); }).join(" ");
    if (/siem|log|ids|monitor/.test(n)) return "monitoreo";
    if (/dato|db|sql|base/.test(n)) return "datos";
    if (/mant|admin|tacacs|bastion|gesti/.test(n)) return "gestion";
    return "privada";
  }
  function proponerZonas(inv) {
    var activos = (inv.activos || []).filter(function (a) { return a.destino !== "No aplica"; });
    var redes = {};
    activos.forEach(function (a) {
      if (a.destino !== "Migrar a instancia en la nube") return;
      (a.redes || []).forEach(function (r) { redes[r] = 1; });
    });
    var n = 0;
    return Object.keys(redes).filter(function (r) { return rangoPrivado(r); }).map(function (r) {
      n++; return { id: "Z-" + String(n).padStart(2, "0"), nombre: "Subred " + r, cidr: r, tipo: tipoZonaDe(r, activos) };
    });
  }
  function rangoPrivado(cidr) { return root.CML ? root.CML.esPrivada(cidr.split("/")[0]) : /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(cidr); }
  function proponerInstancias(inv, zonas) {
    var out = [], n = 0;
    (inv.activos || []).forEach(function (a) {
      if (a.destino !== "Migrar a instancia en la nube") return;
      var red = (a.redes || []).filter(rangoPrivado)[0] || "";
      var z = zonas.filter(function (z) { return z.cidr === red; })[0];
      n++; out.push({ id: "I-" + String(n).padStart(2, "0"), nombre: a.nombre, zona: z ? z.id : "", publica: false, tamano: "1 vCPU / 1 GB", so: a.tipo, activo: a.id });
    });
    return out;
  }
  function reglasBase(zonas) {
    var por = function (t) { return zonas.filter(function (z) { return z.tipo === t; })[0]; };
    var out = [], n = 0, g = por("gestion"), d = por("datos"), m = por("monitoreo"), all = zonas.map(function (z) { return z.id; });
    function add(nombre, dir, proto, puerto, origen, destino, accion) { n++; out.push({ id: "G-" + String(n).padStart(2, "0"), nombre: nombre, dir: dir, proto: proto, puerto: puerto, origen: origen, destino: destino, accion: accion }); }
    if (g && all.length > 1) add("Administración SSH solo desde la zona de gestión", "entrada", "tcp", "22", g.id, "todas", "permitir");
    if (m) add("Envío de registros al SIEM (syslog)", "entrada", "udp", "514", "todas", m.id, "permitir");
    if (d) add("Acceso a datos solo por TLS desde la red interna", "entrada", "tcp", "443", "red interna", d.id, "permitir");
    add("Denegar todo lo demás", "entrada", "any", "any", "any", "todas", "denegar");
    return out;
  }

  var api = { auditar: auditar, puertoIncluye: puertoIncluye, esInternet: esInternet, proponerZonas: proponerZonas, proponerInstancias: proponerInstancias, reglasBase: reglasBase };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.AUD = api;
})(typeof window !== "undefined" ? window : globalThis);
