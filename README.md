# RiskAndes · Matriz de Riesgos CoopAndes Digital

Sistema web estático (un solo `index.html`, sin librerías ni backend) para gestionar una matriz de riesgos de ciberseguridad con **R = Probabilidad × Impacto**.

Asignatura: Diseño de Arquitectura de Redes Seguras · Docente: Daniel Ruz Moreno · Sede La Serena

## Datos del grupo

| Campo | Valor |
|---|---|
| Grupo | N (reemplazar) |
| Integrantes | _completar_ |
| Repositorio | `https://github.com/<usuario>/matriz-riesgo-grupoN` _(completar)_ |
| URL publicada | `https://matriz-riesgo-grupoN.pages.dev` _(completar tras el despliegue)_ |

## Funcionalidades mínimas (guía de la actividad)

- Formulario: ID, activo, amenaza, vulnerabilidad, P (1–5), I (1–5) y **fuente del dato obligatoria**.
- Cálculo automático de R = P × I con nivel, color y acción: 1–5 Bajo (Monitorear), 6–9 Medio (Mejorar controles), 10–16 Alto (Intervenir pronto), 17–25 Crítico (Intervenir ya).
- Tabla ordenada de mayor a menor riesgo y matriz de calor 5×5 con el ID en cada celda.
- Control propuesto y riesgo residual (P e I posteriores al control).

## Componente creativo (mejoras propias)

1. **Identidad visual**: nombre RiskAndes, logotipo SVG, paleta propia y modo claro/oscuro.
2. **Panel resumen** con contadores por nivel y % de reducción total del riesgo tras los controles.
3. **Comparación inherente vs. residual**: gráfico de barras por nivel, matriz de calor conmutable y columna "inherente → residual" por riesgo.
4. **Catálogo de 12 amenazas** que autocompleta activo, amenaza, vulnerabilidad, control y controles **ISO/IEC 27001:2022 (Anexo A)**.
5. **Filtros y búsqueda** por texto, nivel y activo; orden por columna.
6. **Persistencia** en `localStorage`, **exportación a CSV** (protegida contra inyección de fórmulas) e **impresión/PDF** con vista de informe.

## Registro de validación (casos de prueba)

El botón "Ejecutar casos de prueba" de la página ejecuta la misma función de cálculo del sistema. También se verificó fuera del navegador con Node.js.

| P | I | Esperado | Obtenido | Corrección |
|---|---|---|---|---|
| 4 | 5 | 20 – Crítico | 20 – Crítico | Ninguna |
| 2 | 3 | 6 – Medio | 6 – Medio | Ninguna |
| 3 | 5 | 15 – Alto | 15 – Alto | Ninguna |
| 4 | 4 | 16 – Alto | 16 – Alto | Ninguna |
| 1 | 5 | 5 – Bajo | 5 – Bajo | Ninguna |

> **Registrar aquí los errores de la IA** que detecte el grupo (requisito de la actividad). Ejemplos a revisar: fronteras de nivel (5/6, 9/10, 16/17), que el residual no supere al inherente, escape de HTML en los textos ingresados, y el orden de la tabla.

## Caso CoopAndes Digital: 6 hallazgos cargados

| ID | Hallazgo | P | I | Inherente | Control propuesto | P res. | I res. | Residual |
|---|---|---|---|---|---|---|---|---|
| R-01 | Bucket S3 de respaldos con lectura pública | 5 | 4 | 20 Crítico | Block Public Access, mínimo privilegio, SSE-KMS, versionado | 1 | 3 | 3 Bajo |
| R-02 | SSH (22) y RDP (3389) abiertos a 0.0.0.0/0 | 5 | 4 | 20 Crítico | Cerrar puertos; VPN/Session Manager con MFA | 1 | 4 | 4 Bajo |
| R-03 | Cuenta root sin MFA usada por 3 personas | 3 | 5 | 15 Alto | MFA físico, usuarios nominales, alarma de uso de root | 1 | 5 | 5 Bajo |
| R-04 | BD del portal con IP pública y sin cifrar | 4 | 5 | 20 Crítico | Subred privada, cifrado en reposo y TLS | 1 | 4 | 4 Bajo |
| R-05 | Sin registro de actividad en la nube | 3 | 4 | 12 Alto | Trail multi-región, almacenamiento inmutable, alertas | 2 | 2 | 4 Bajo |
| R-06 | Rack on premise sin acceso controlado y respaldos sin prueba | 3 | 4 | 12 Alto | Control de acceso + CCTV; respaldos 3-2-1 con pruebas | 2 | 3 | 6 Medio |

Riesgo más crítico: empatan R-01, R-02 y R-04 con 20. R-04 combina el mayor impacto (datos personales y financieros, exposición legal). La mayor caída de nivel la tienen R-01, R-02 y R-04, que bajan de Crítico a Bajo.

### Sobre las fuentes de datos

El caso no entrega estadísticas de incidentes, por lo que la justificación de cada P e I se apoya en la escala de la Guía Didáctica y en cómo se verifica cada hallazgo (AWS Config, IAM Credential Report, Security Groups, etc.). **Si el grupo dispone de evidencia propia** (capturas, informes, cifras de un tercero), debe reemplazar el texto del campo "Fuente del dato".

## Publicación en Cloudflare Pages

1. Subir el repositorio a GitHub (público, `matriz-riesgo-grupoN`).
2. Cloudflare → Workers & Pages → Create → Pages → Connect to Git → elegir el repositorio.
3. Framework preset: **None** · Build command: _(vacío)_ · Output directory: `/` (raíz).
4. Nombre del proyecto `matriz-riesgo-grupoN` → URL `*.pages.dev`. Cada `git push` redespliega.

```bash
git remote add origin https://github.com/<usuario>/matriz-riesgo-grupoN.git
git branch -M main
git push -u origin main
```

## Evaluación final: sistema de migración a la nube

La misma aplicación (sin backend, solo archivos estáticos) se amplió a cinco secciones que comparten datos en el navegador:

| Página | Qué hace |
|---|---|
| `index.html` · Matriz de riesgos | Matriz R = P × I, mapa de calor, residual y catálogo ISO (la actividad original). Botones para vaciar la matriz o restablecer el caso CoopAndes. |
| `inventario.html` · Inventario | **Importa el laboratorio CML (.yaml)**: nodos, enlaces, IP, redes y VLAN, y dibuja la topología. Sugiere vulnerabilidades por activo, que se validan y vinculan a riesgos de la matriz. Botón «→ Riesgo» para crear uno desde un activo. |
| `migracion.html` · Migración | Plan por fases (plantilla de 5, con plan de reversa obligatorio, activos asignados y cronograma), plan de contingencia (plantilla de 6 escenarios con RTO/RPO) y gestión de seguridad con controles ISO/IEC 27001:2022. |
| `nube.html` · Nube | Zonas, instancias y reglas de firewall. Genera una propuesta desde el inventario y **audita las reglas** (SSH/RDP o bases de datos abiertas a Internet, IP pública en zonas privadas, falta de segmentación, etc.). |
| `informe.html` · Informe | Informe resumen conciso con portada, KPIs, topología, mapas de calor, plan y auditoría. Se exporta a **PDF** (imprimir), **Excel .xlsx** de 10 hojas y respaldo **.json**. Incluye una lista de revisión previa a la entrega. |

Archivos de apoyo: `styles.css` (estilos), `common.js` (cálculo de riesgo, almacenamiento, tablas/formularios, generador de .xlsx), `cml.js` (importador de CML) y `audit.js` (auditor de reglas y propuestas).

### Cómo usarlo cuando el docente entregue el CML

1. **Inventario** → elegir el `.yaml` exportado de CML → «Importar topología». Se crean los activos con IP, redes, conexiones y vulnerabilidades sugeridas.
2. Validar vulnerabilidades, fijar la **criticidad** y el **destino de migración** de cada activo (migrar a instancia, reemplazar por servicio nativo, mantener, retirar).
3. **Matriz de riesgos** → «Vaciar matriz» y registrar los riesgos del caso (usa «→ Riesgo» desde el inventario); luego vincularlos a los activos.
4. **Migración** → cargar plantillas de fases y contingencia, completar fechas y responsables; sincronizar controles ISO.
5. **Nube** → generar propuesta, ajustar zonas/instancias, agregar reglas base y corregir hallazgos de la auditoría.
6. **Informe** → completar la portada, resolver los pendientes de la revisión y exportar PDF y Excel.

### Seguridad y privacidad del importador

- El archivo CML se procesa en el navegador; no se sube a ningún servidor.
- Se extraen solo datos de red. **El texto de la configuración se descarta**: contraseñas, claves de enable, PSK de VPN y secretos de TACACS no se guardan ni aparecen en el informe (verificado con el laboratorio de prueba). Solo se mencionan como hallazgo, sin su valor.
- Todo texto ingresado se muestra con `textContent` (sin HTML), y los CSV/Excel neutralizan fórmulas (`=`, `+`, `-`, `@`).

### Límites a considerar

- El importador espera el YAML de **exportación estándar de CML** (formato en bloques). Con otro formato mostrará un error y se puede ingresar el inventario a mano.
- Las vulnerabilidades sugeridas son **heurísticas** sobre la configuración (contraseñas locales, PSK, sin syslog/AAA, SSH por contraseña, etc.): el estudiante debe validarlas.
- Plantillas de RTO/RPO y tamaños de instancia son ejemplos a ajustar.
- Los datos viven en el `localStorage` del navegador: respaldar con el `.json` del Informe.
- Pruebas realizadas: importador probado con un laboratorio CML real de otra unidad (14 nodos, 14 enlaces), 58 verificaciones automáticas del flujo completo en jsdom y lectura del .xlsx con openpyxl. **No se probó en un navegador real** (la apariencia y la impresión a PDF deben revisarse a mano).

### Fechas de la evaluación (según el resumen de clase)

El resumen menciona «diseño: viernes 18 de diciembre» y «entrega final: 13 de diciembre», que parecen contradecirse. Conviene confirmar las fechas con el docente.
