# Guía de Splunk — Carga de datos, búsquedas SPL y dashboards

> **IMPORTANTE para la demo**: al correr cualquier búsqueda, poner el rango de tiempo (arriba a la
> derecha) en **"Last 7 days"** o **"All time"**. Los datos del incidente simulado de CFP son del
> 2026-07-16; el dataset real de OTRF es del 2021-03-14. Con "Last 24 hours" no se verían.

## 1. Crear el índice

`Settings > Indexes > New Index` → nombre `proxylogon` (o el que prefieran, ajustar en todas las
búsquedas de abajo). Todo lo demás por defecto.

## 2. Cargar los datasets

`Settings > Add Data > Upload` (más simple para datasets históricos que un forwarder).

### 2.1 Archivo `data/iis_logs.log`
- Subir el archivo.
- **Sourcetype**: seleccionar `iis` en la lista (Splunk lo reconoce nativamente por el header
  `#Fields:` en formato W3C Extended Log Format). Si no aparece exactamente `iis`, usar la vista
  previa (`Preview`) para confirmar que Splunk separa correctamente cada línea en un evento y que
  reconoce `date`+`time` como el timestamp del evento (no la hora de carga).
- **Índice**: `proxylogon`.
- **Host**: `EXCH01` (manual).
- Revisar en el preview que el timestamp de los eventos corresponda a `2021-03-02`, NO a la fecha de
  hoy. Si Splunk está tomando la fecha de carga, ajustar manualmente en el paso de preview: "Configure
  timestamp" → seleccionar el campo `date`/`time` extraído del log.

### 2.2 Archivo `data/windows_events.log`
- Subir el archivo.
- **Sourcetype**: crear uno nuevo llamado `windows_events_proxylogon` (botón "New sourcetype" en el
  wizard).
- **Índice**: `proxylogon`.
- **Host**: `EXCH01`.
- Splunk extrae automáticamente los pares `clave=valor` sin configuración adicional (extracción
  automática de key-value está activa por defecto en cualquier búsqueda).
- **Timestamp**: cada línea empieza con `TimeCreated=2021-03-02T09:46:46.000Z` (formato ISO 8601).
  En el preview, verificar que Splunk lo reconozca automáticamente; si no, configurar manualmente:
  `TIME_PREFIX = TimeCreated=` y `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ`.

### 2.3 Validar la carga
Correr esta búsqueda de control antes de construir nada más:

```spl
index=proxylogon | stats count by sourcetype
```

Deben aparecer los ~300 eventos de `iis` y ~32 eventos de `windows_events_proxylogon`. Si algún
campo no se extrajo (ej. `c_ip` vacío), revisar el nombre exacto con:

```spl
index=proxylogon sourcetype=iis | head 1 | table *
```

Los nombres de campo de IIS pueden variar levemente según la versión de Splunk (ej. `cs_User_Agent`
vs `cs_UserAgent`) — ajustar las búsquedas de abajo con los nombres reales que vean en su instancia.

## 2.4 Cargar los lookups de threat intelligence real (IOCs publicados)

Splunk publicó su propia investigación de detección para este ataque exacto ("Detecting HAFNIUM
Exchange Server Zero-Day Activity in Splunk") y compiló IOCs reales (reportados por Volexity,
Microsoft y Huntress Labs) en 3 tablas CSV, disponibles públicamente en
[github.com/stressboi/hafnium-exchange-splunk-csvs](https://github.com/stressboi/hafnium-exchange-splunk-csvs).
Ya están copiadas en `splunk/lookups/` de este repo:
- `hafnium_ips.csv` — 16 IPs reales de la campaña (la primera es la misma que usamos: `103.77.192.219`).
- `hafnium_webshells.csv` — 31 nombres reales de webshell documentados (usamos `help.aspx`).
- `hafnium_useragents.csv` — user-agents reales que HAFNIUM usó para camuflarse como crawlers.

**Para cargarlos**: `Settings > Lookups > Lookup table files > New Lookup Table File` → subir cada
CSV, destino app `search`. Luego `Settings > Lookups > Lookup definitions > New Lookup Definition`
→ crear una definición del mismo nombre (`hafnium_ips`, `hafnium_webshells`, `hafnium_useragents`)
apuntando al archivo correspondiente.

Esto permite usar el comando `lookup` de Splunk — una función nativa real del SIEM — para
correlacionar automáticamente contra threat intelligence publicada, en vez de solo comparar patrones
de texto hardcodeados. Ver la Regla 1 mejorada abajo.

## 3. Las 5 búsquedas de detección (una por fase del Kill Chain)

Guardar cada una como **Alert** (`Save As > Alert`, condición "Number of results > 0"), para poder
mostrar en la demo que "esto dispararía una alerta real".

### Regla 1 — SSRF / bypass de autenticación (CVE-2021-26855)
```spl
index=proxylogon sourcetype=iis (cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*" OR cs_Cookie="*X-BEResource*")
| table _time c_ip cs_uri_stem cs_uri_query sc_status time_taken
| sort _time
```
**Por qué detecta esto y no más**: el patrón `@dominio` dentro de la query de `/autodiscover/` o
`/ecp/`, o la presencia de las cookies internas de Exchange viniendo de un cliente externo, no
ocurre en tráfico legítimo — esas cookies las genera el propio servidor internamente.

**Versión mejorada con threat intelligence real (usar esta en la demo si ya cargaron el lookup
`hafnium_ips` de la sección 2.4)**:
```spl
index=proxylogon sourcetype=iis (cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*" OR cs_Cookie="*X-BEResource*")
| lookup hafnium_ips src_ip AS c_ip OUTPUT isBad AS ip_conocida_hafnium
| table _time c_ip ip_conocida_hafnium cs_uri_stem cs_uri_query sc_status time_taken
| sort _time
```
Esto agrega la columna `ip_conocida_hafnium=TRUE` cuando la IP de origen coincide con una de las 16
IPs reales publicadas por Volexity/Microsoft/Huntress Labs para esta campaña — pasa de "el patrón se
ve raro" a "esta IP es un IOC confirmado de HAFNIUM", que es un argumento mucho más fuerte en el
triage. Buen momento para explicar el comando `lookup` como feature nativa del SIEM en la rúbrica.

### Regla 2 — Escritura del webshell (CVE-2021-27065)
```spl
index=proxylogon sourcetype=iis
((cs_uri_stem="/ecp/proxyLogon.ecp" cs_method=POST) OR (cs_uri_stem="/owa/auth/help.aspx" cs_method=GET))
| table _time c_ip cs_method cs_uri_stem sc_status time_taken
| sort _time
```
**Por qué detecta esto**: muestra las 2 mitades de la instalación del webshell — el POST que lo
escribe (`/ecp/proxyLogon.ecp`) seguido, 15 segundos después, del GET que confirma que quedó
accesible (`/owa/auth/help.aspx`).

**Nota para la ronda de preguntas**: una alternativa que se evaluó fue usar el comando `transaction`
de Splunk (función nativa para correlacionar secuencias de eventos por proximidad temporal — POST
seguido de GET desde la misma IP en <2 minutos). Es un buen ejemplo de "propiedad propia del SIEM"
para la rúbrica. Se optó por la versión con rutas específicas por ser más determinística y legible,
pero conviene mencionar `transaction` como la técnica de correlación que se consideró.

### Regla 3 — Ejecución de comandos vía webshell (C2)
```spl
index=proxylogon sourcetype=windows_events_proxylogon EventCode=4688 ParentProcessName="*w3wp.exe*"
| table _time Computer NewProcessName ParentProcessName CommandLine
| sort _time
```
**Por qué**: el proceso de IIS/Exchange (`w3wp.exe`) generando `cmd.exe` o `powershell.exe` como
hijo nunca ocurre en operación normal de Exchange.

### Regla 4 — Exportación masiva de buzones
```spl
index=proxylogon sourcetype=windows_events_proxylogon EventCode=4104 ScriptBlockText="*New-MailboxExportRequest*"
| table _time Computer ScriptBlockText
```
**Por qué**: exportar un buzón completo a `.pst` es una operación administrativa infrecuente y
sensible; el triage debe validar si estaba dentro de una ventana de migración planificada.

### Regla 5 — Acceso a LSASS (credential dumping)
```spl
index=proxylogon sourcetype=windows_events_proxylogon EventCode=10 TargetProcessName="*lsass.exe*"
NOT SourceProcessName IN ("*MsMpEng.exe*", "*procexp*", "*Taskmgr.exe*")
| table _time Computer SourceProcessName TargetProcessName GrantedAccess
```
**Por qué**: se excluyen procesos legítimos conocidos que acceden a LSASS (antivirus, Task Manager)
para reducir falsos positivos — este es justamente el tipo de ajuste ("tuning") que se documenta en
el plan de triage.

### Búsqueda bonus — línea de tiempo completa del ataque (para la demo en vivo)
```spl
index=proxylogon (sourcetype=iis c_ip="103.77.192.219") OR (sourcetype=windows_events_proxylogon ParentProcessName="*w3wp.exe*" OR EventCode=4104 OR EventCode=10)
| eval evento=case(
    match(cs_uri_query,"@"), "SSRF Autodiscover",
    cs_uri_stem="/ecp/proxyLogon.ecp", "Escritura webshell (POST)",
    cs_uri_stem="/owa/auth/help.aspx", "Acceso al webshell",
    EventCode=4688, "Ejecucion de comando via w3wp.exe",
    EventCode=4104, "Exportacion de buzon",
    EventCode=10, "Acceso a LSASS",
    1=1, "Otro")
| table _time evento sourcetype c_ip CommandLine ScriptBlockText
| sort _time
```
Esta es la búsqueda estrella para la sustentación: muestra las 7 fases del ataque en orden
cronológico en una sola tabla.

### Regla 6 — Validación cruzada con dataset real (OTRF)
No es una regla de detección sobre nuestro escenario simulado, sino una prueba de que las mismas
reglas funcionarían sobre una ejecución **real** del exploit público:
```spl
index=proxylogon sourcetype=_json EventID=1 ParentImage="*w3wp*"
| table TimeCreated Hostname Image ParentImage CommandLine
| sort TimeCreated
```
**Fuente del dato**: [OTRF (Open Threat Research Forge) — Security-Datasets](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-210314014019.html),
un dataset público de eventos Sysmon capturados en 2021-03-14 al ejecutar el POC público de
ProxyLogon (CVE-2021-26855) contra un Exchange real de laboratorio (`MXS01.azsentinel.local`). Este
comando muestra el evento real: `w3wp.exe` generando `cmd.exe` con `cmd /c whoami` — el mismo
artefacto exacto que representamos en el dataset sintético, pero capturado de una ejecución
verdadera, no simulada. Este es el argumento más fuerte para defender que el diseño de detección es
válido, no solo "se ve razonable en la teoría".

También quedó en la evidencia cruda de ese dataset (mismo `sourcetype=json_otrf_real`) el payload
literal usado por el exploit real vía `Set-OabVirtualDirectory` (la técnica exacta de CVE-2021-27065,
un webshell JScript inyectado en el parámetro `-ExternalUrl`):
```spl
index=proxylogon sourcetype=json_otrf_real SourceName="MSExchange CmdletLogs" Message="*OabVirtualDirectory*"
| table TimeCreated Message
```

### Regla 7 — Prueba de falsos positivos (debe dar siempre 0)
Exigido explícitamente por el profesor en la aprobación de la propuesta ("no olvidar (...) confirmar
que no es un Falso Positivo"). Se corre la Regla 1 pero filtrando solo IPs internas de la
organización — si algo aparece, hay que afinar la regla:
```spl
index=proxylogon sourcetype=iis c_ip="192.168.1.*"
(cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*" OR cs_Cookie="*X-BEResource*")
| stats count as falsos_positivos_regla1
```
Resultado verificado: **0**. Repetir el mismo patrón (filtrar a solo tráfico/procesos benignos) es
la evidencia cuantitativa de bajo FP que se puede mostrar en vivo durante el triage.

### Panel adicional en el dashboard: Fase 5c — Exfiltración (descarga del .pst)
Después de exportar el buzón a un `.pst` en una carpeta web-accesible, el atacante lo descarga vía
HTTP a través del propio webshell. Se ve en los logs de IIS como un GET a un `.pst` con un
`time-taken` muy alto (transferencia grande):
```spl
index=proxylogon sourcetype=iis cs_uri_stem="*.pst"
| table _time c_ip cs_method cs_uri_stem sc_status time_taken
```
Resultado: `GET /aspnet_client/backup.pst` desde `103.77.192.219`, `time-taken=5200ms` — la última
fase del kill chain.

### Nota sobre la limpieza del índice (por si preguntan por qué el SPL es tan limpio)
Durante el desarrollo se hicieron varias iteraciones del dataset (se fue mejorando con IOCs reales a
medida que se investigaba — ver `00_PLAN_MAESTRO.md`). Al final se **vació el índice por completo**
(`splunk clean eventdata -index proxylogon`) y se recargaron los datasets finales una sola vez, de
modo que las reglas quedaron con SPL simple y directo, sin `dedup` ni exclusiones de datos antiguos.
Buen ejemplo de higiene de datos en un SIEM: un índice limpio hace las detecciones más legibles y
mantenibles.

### Regla 2 mejorada — patrón oficial de Microsoft (opcional, mayor precisión)
El script oficial de Microsoft [`Test-ProxyLogon.ps1`](https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/Test-ProxyLogon.ps1)
busca literalmente los patrones `Reset*VirtualDirectory#` y `Set-*VirtualDirectory` en los logs de
ECP para detectar CVE-2021-27065. Si se quiere una Regla 2 más cercana a la detección oficial de
Microsoft (en vez de solo "POST a /ecp/ seguido de GET a .aspx"), se puede añadir esa condición:
```spl
index=proxylogon sourcetype=iis cs_uri_stem="*/ecp/*" (cs_uri_query="*Set-*VirtualDirectory*" OR cs_uri_query="*Reset*VirtualDirectory*")
```
No reemplaza la Regla 2 actual (que ya está probada y funcionando) — se documenta como mejora
opcional y como demostración de que conocemos la detección oficial de Microsoft, útil para la ronda
de preguntas.

## 4. Dashboards (mínimo 2 pedidos por la rúbrica)

### Dashboard 1 — Overview
- Panel de línea de tiempo: `index=proxylogon | timechart span=1h count by sourcetype` (gráfico de
  picos de tráfico requerido por la rúbrica).
- 5 paneles "single value" con el conteo de cada una de las 5 reglas (usar cada SPL de arriba con
  `| stats count`).
- Panel de top IPs origen en IIS: `index=proxylogon sourcetype=iis | top limit=10 c_ip`.

### Dashboard 2 — Detalle por fase
- Un panel de tabla por cada una de las 5 reglas (las búsquedas completas, no solo el conteo).
- Panel de línea de tiempo completa (búsqueda bonus).
- Panel final: validación cruzada contra el dataset real de OTRF (Regla 6) — este es el que más
  impacto tiene si el profesor pregunta "¿esto es real o inventado?".

## 5. Resumen de las 7 búsquedas guardadas en Splunk
1. `01 - ProxyLogon SSRF Autodiscover Bypass` (con lookup real, filtrado a IOC confirmado)
2. `02 - ProxyLogon Webshell Drop`
3. `03 - ProxyLogon C2 via Webshell (w3wp child process)`
4. `04 - ProxyLogon Mailbox Export`
5. `05 - ProxyLogon LSASS Access`
6. `06 - Validacion con dataset real OTRF (ejecucion real del exploit)`
7. `07 - Prueba de Falsos Positivos (debe dar 0)`

## 6. Checklist de verificación antes de la demo
- [ ] Los timestamps de los eventos son del 2021-03-02, no la fecha de hoy.
- [ ] Las 5 búsquedas devuelven resultados (probarlas todas una vez más el día antes).
- [ ] Los dashboards cargan sin errores de campo faltante.
- [ ] Video de respaldo grabado por si la demo en vivo falla.
