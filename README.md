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

## Relación con la evaluación 3 y 4

Esta actividad es la base de la evaluación final (sistema web que genera automáticamente el informe de migración a la nube). Pendiente de ampliar: inventario de activos de la topología CML, plan de migración y contingencia, y generación de informe PDF/Excel resumido.
