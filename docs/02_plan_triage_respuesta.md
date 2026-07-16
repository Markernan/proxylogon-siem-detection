# Plan de Triage, Confirmación y Respuesta al Incidente — ProxyLogon

Este documento cubre dos entregables de la rúbrica:
- **Plan de triage y confirmación del ataque** (parte de los 15 pts de SIEM).
- **Plan de respuesta al incidente** (parte de los 5 pts de análisis técnico).

## Parte A — Triage y confirmación (rol: Analista SOC Nivel 1)

Escenario de disparo: en el SOC de **Corporación Financiera del Pacífico S.A. (CFP)**, la alerta 1
(SSRF/bypass de autenticación) salta en Splunk a las 09:45:03, generada por una petición desde
`103.77.192.219` hacia el servidor Exchange corporativo (`EXCH01.cfp-financiera.local`), dirigida a
`/autodiscover/autodiscover.json` con `@` en la query string. El analista Nivel 1 recibe la alerta y
sigue estos pasos:

### 1. Evaluación inicial (¿qué tenemos?)
- **Qué la generó**: regla "ProxyLogon - SSRF Autodiscover Bypass" (ver `03_guia_splunk.md`).
- **Timestamp**: 2021-03-02 09:45:03.
- **Severidad asignada por la regla**: Alta (toca directamente el frontend de Exchange expuesto).
- **Entidades involucradas**: IP origen `103.77.192.219` (externa), host destino `EXCH01.cfp-financiera.local`
  (`10.10.20.15`).
- **Logs que generaron la alerta**: 6 eventos en `iis_logs.log` entre 09:45:00 y 09:45:15.

### 2. Triage — ¿tiene sentido lógico?
- Una IP externa (`103.77.192.219`, fuera del rango interno `192.168.1.0/24`) no debería estar
  generando tráfico hacia `/autodiscover/` con sintaxis `@dominio-externo` — ese patrón nunca lo usa
  un cliente Outlook/OWA legítimo.
- Búsqueda adicional en Splunk: `index=proxylogon sourcetype=iis c_ip="103.77.192.219"` — confirma que
  esta IP **solo** aparece en el contexto de la explotación, nunca en tráfico previo de usuarios
  legítimos (a diferencia de las IPs internas `192.168.1.x`, que sí tienen historial normal).
- Revisar el campo `time-taken`: 8ms, extremadamente rápido para una consulta real de Autodiscover —
  consistente con una petición automatizada/scripteada, no un cliente real.

### 3. Recopilación de información adicional (enriquecimiento)
- **VirusTotal**: consultar la IP `103.77.192.219` en VirusTotal (`https://www.virustotal.com/gui/ip-address/103.77.192.219`)
  para revisar reputación, si aparece en otros reportes de malware/C2, y su geolocalización/ASN.
  - *Nota*: esta IP no es inventada — es uno de los indicadores de compromiso reales de la campaña
    HAFNIUM/ProxyLogon, publicado en el advisory conjunto de CISA (AA21-062A) y usado también por
    Microsoft/Volexity en sus reportes. Se eligió deliberadamente en vez de una IP de rango reservado
    (RFC 5737) para que la consulta en VirusTotal muestre reputación y contexto real durante la demo.
- **Correlación cruzada en Splunk**: buscar si la misma IP aparece en los Windows Event Logs (no
  debería, porque el ataque llega vía red, no localmente) y si hay otras alertas de las 5 reglas
  disparadas por la misma IP/host en una ventana de tiempo cercana — así se arma la cadena completa.
- **Timeline en Splunk**: usar el panel de timeline (`timechart count by rule_name`) para visualizar
  que las 5 alertas ocurren en secuencia dentro de ~10 minutos — un patrón de "ataque en cadena", no
  eventos aislados.

### 4. Categorización
- **Falso Positivo (FP)**: descartado — no hay ningún proceso de negocio legítimo que explique tráfico
  externo con sintaxis de bypass SSRF hacia Autodiscover.
- **Verdadero Positivo (TP)**: confirmado, con alta confianza, dado que:
  1. El patrón de URI coincide exactamente con el IOC público de ProxyLogon.
  2. Está seguido, en la misma ventana de tiempo, por la escritura de un archivo `.aspx` nuevo y la
     ejecución de comandos vía `w3wp.exe` — imposible de explicar como actividad benigna.

### 5. Prioridad final
**Crítica** — servidor de correo corporativo comprometido con ejecución remota de código confirmada.

### 6. Escalamiento
Se escala inmediatamente a Nivel 2 (Resolución de Incidentes) y se activa el plan de respuesta
(Parte B), dado que se confirmó un incidente grave que requiere contención y coordinación con TI.

## Parte B — Plan de respuesta al incidente (marco NIST SP 800-61 / SANS PICERL)

### Preparación (ya vigente antes del incidente)
- Inventario de activos críticos (Exchange está clasificado como Crítico dentro de CFP — CIA:
  Confidencialidad e Integridad Altas por contener correo corporativo con datos financieros y
  personales de clientes).
- Splunk con las 5 reglas de correlación activas y notificando al canal del SOC.
- Contactos predefinidos: Admin. de Redes (para bloqueo en firewall), TI (para aislar el host), Legal
  y Oficial de Cumplimiento (si hay datos personales comprometidos, dado el rol regulado de CFP como
  entidad financiera), Área de Comunicaciones (para eventual notificación a clientes/SBS).

### Detección y Análisis
- Cubierto en la Parte A. Al confirmarse el TP, se documenta: alcance (1 servidor Exchange), impacto
  potencial (posible exfiltración de buzones vía `.pst`), y causa raíz preliminar (CVE-2021-26855 /
  CVE-2021-27065 sin parchear).

### Contención
- **Corto plazo**: bloquear la IP `103.77.192.219` en el firewall perimetral; deshabilitar temporalmente
  el acceso público a `/ecp/` y `/owa/` si es viable operativamente, o al menos el archivo webshell
  identificado (`/owa/auth/help.aspx`).
- **Largo plazo**: aislar el servidor Exchange de segmentos de red no esenciales mientras se investiga
  el alcance completo (ej. revisar si hubo movimiento lateral a otros servidores usando las
  credenciales potencialmente volcadas de LSASS).

### Erradicación
- Eliminar el archivo webshell y cualquier otro artefacto de persistencia encontrado durante la
  investigación (tareas programadas, cuentas nuevas, servicios no reconocidos).
- Aplicar el parche acumulativo de Exchange correspondiente a marzo de 2021 (o la herramienta de
  mitigación de emergencia de Microsoft — el "Exchange On-Premises Mitigation Tool" — si el parcheo
  inmediato no es viable).
- Rotar todas las credenciales de cuentas de servicio de Exchange y forzar cambio de contraseña de
  cuentas cuyo buzón fue potencialmente exportado.

### Recuperación
- Restaurar el servicio desde una imagen limpia si se sospecha persistencia adicional (webshells
  ocultos, tareas programadas) o, si el análisis forense descarta eso, restaurar el archivo eliminado
  a su estado original y reactivar el servicio en producción.
- Monitoreo reforzado (ventana de 30 días) sobre el host afectado y sobre el rango de IPs asociado al
  atacante.
- Validar funcionamiento normal de OWA/ECP/Autodiscover con usuarios piloto antes de reabrir a toda
  la organización.

### Comunicación y notificación regulatoria (específico al sector financiero de CFP)
Por ser CFP una entidad financiera regulada, la respuesta no termina en lo técnico:
- **Superintendencia de Banca, Seguros y AFP (SBS)**: se notifica conforme a la normativa de gestión
  de riesgo operacional y ciberseguridad aplicable al sistema financiero peruano, dado que el
  incidente afecta un activo crítico con ejecución remota de código confirmada.
- **Autoridad Nacional de Protección de Datos Personales**: se evalúa notificación si el análisis
  forense confirma que se exportaron o exfiltraron datos personales de clientes (Ley N.° 29733),
  típicamente dentro del plazo que exige la norma una vez confirmado el alcance.
- **Clientes afectados**: si se confirma exposición de datos personales o financieros específicos,
  se comunica de forma directa y transparente, con foco en qué pasó, qué datos se vieron
  potencialmente comprometidos, y qué acciones preventivas se recomiendan (ej. monitoreo de
  actividad inusual en sus productos).
- **Comunicación interna**: Directorio y Gerencia General informados desde la confirmación del TP
  (prioridad Crítica), dado el rol de la información comprometida y el riesgo reputacional propio de
  una entidad financiera.

### Lecciones aprendidas / Informe post-incidente
- **Resumen ejecutivo**: explotación de ProxyLogon en el servidor Exchange corporativo de Corporación
  Financiera del Pacífico S.A. (CFP), detectada por el SIEM en <1 minuto desde el primer indicio de
  SSRF, contenida en X minutos desde la confirmación.
- **Causa raíz**: parche crítico de marzo 2021 no aplicado a tiempo (o servidor no gestionado bajo el
  ciclo de parcheo estándar).
- **Recomendaciones**: (1) reducir el SLA de aplicación de parches críticos en sistemas expuestos a
  Internet, (2) evaluar migración a Exchange Online o segmentación adicional del servidor on-premise,
  (3) desplegar un EDR en el servidor Exchange para visibilidad adicional a nivel de proceso/memoria,
  (4) agregar una regla de SIEM que alerte específicamente por parches faltantes conocidos en activos
  críticos.
