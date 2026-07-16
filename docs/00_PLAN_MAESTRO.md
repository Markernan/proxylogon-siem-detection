# Plan Maestro — Proyecto ProxyLogon (Detección SIEM)

## Estado del equipo
- **Equipo**: 2 personas (originalmente 3, un integrante no continuó).
- **Plazo**: 4 días desde el 13/07/2026 hasta la sustentación.
- **Alcance elegido**: SOLO detección SIEM (no SOAR/TheHive). La rúbrica dice "escoger uno".
- **Herramienta SIEM**: Splunk, instalado y corriendo en `http://26.28.194.96:8000`.

## Rúbrica objetivo (35 pts posibles en esta modalidad)
1. **Análisis técnico y lógico del ataque — 5 pts**: Kill Chain, operación técnica detallada
   (vulnerabilidades, herramientas, flujo), evidencia digital y artefactos, equipos que producirían
   la evidencia + plan de respuesta al incidente.
2. **Detección SIEM — 15 pts**: mecanismos de detección (alertas basadas en evidencia real), mínimo
   2 fuentes de logs cargadas en el SIEM, plan de triage y confirmación (búsquedas adicionales,
   enriquecimiento con threat intel tipo VirusTotal, uso de features nativas del SIEM: gráficos de
   picos de tráfico, timeline de eventos).
3. **Factores blandos** (sin puntaje propio pero definen la nota final): dominio de la simulación por
   AMBOS integrantes, conocimiento de la implementación de Splunk, conocimiento profundo del ataque
   real, capacidad de responder preguntas adicionales del profesor en vivo.

## Decisión de diseño 1: anclar todo a ProxyLogon real, no inventar patrones
Cada log sintético representa un artefacto real y documentado del ataque ProxyLogon (marzo 2021,
Microsoft Exchange Server), reportado públicamente por Microsoft (MSTIC) y Volexity ("Operation
Exchange Marauder"). Defendible ante cualquier pregunta tipo "¿por qué ese patrón?" con "porque así
lo reportaron las fuentes primarias", que es justo lo que pide el enunciado del curso.

## Decisión de diseño 2: formato de logs nativo, no JSON genérico
Se descartó usar JSON normalizado (enfoque típico de un pipeline Elasticsearch). En su lugar:
- **IIS**: formato **W3C Extended Log Format** (texto plano tal como lo produce IIS realmente).
  Splunk lo reconoce con el sourcetype nativo `iis`/`ms:iis:*` sin configuración adicional.
- **Windows Event Logs**: líneas de texto `clave=valor` (como se ven los eventos de Windows/Sysmon
  cuando Splunk los indexa vía su Add-on oficial para Windows). Splunk extrae estos campos
  automáticamente (`kv_mode=auto`), sin tocar `props.conf`.

Razones: (a) cero riesgo de parsing roto el día crítico, (b) se ve más auténtico en la demo que un
JSON inventado, (c) es literalmente el formato que un SOC real vería en Splunk.

## Decisión de diseño 3: mezclar tráfico benigno con el ataque
El dataset no es "puro ataque" — incluye tráfico normal de usuarios (logins válidos a OWA, requests
normales de Outlook/Autodiscover, procesos benignos) para que el ejercicio de triage tenga sentido:
hay que encontrar la aguja en el pajar, no solo mostrar una tabla ya filtrada de eventos maliciosos.

## Cadena de vulnerabilidades ProxyLogon (referencia técnica)
- **CVE-2021-26855 (SSRF, pre-auth)**: el atacante envía un request HTTP a Exchange falsificando el
  header `Cookie: X-AnonResource-Backend=<backend>~<puerto>` junto a una URI manipulada tipo
  `/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com`.
  Esto hace que el frontend de Exchange reenvíe el request a su propio backend autenticándose como si
  fuera un usuario legítimo (server-side request forgery contra sí mismo). Permite robar datos de
  buzones arbitrarios sin credenciales.
- **CVE-2021-26857 (deserialización insegura, Unified Messaging service)**: ejecución de código con
  privilegios SYSTEM, alcanzable vía el contexto obtenido con el SSRF.
- **CVE-2021-26858 / CVE-2021-27065 (escritura arbitraria de archivos, post-auth)**: usando el
  contexto autenticado obtenido vía SSRF, el atacante abusa de funciones de administración de Exchange
  (ej. Set-OabVirtualDirectory vía ECP) para escribir archivos arbitrarios en el servidor — así se
  deja caer el webshell `.aspx` (de aquí el nombre "ProxyLogon": proxy + logon falsificado). Rutas
  típicas: `\FrontEnd\HttpProxy\owa\auth\`, `\FrontEnd\HttpProxy\ecp\auth\`.

## Secuencia real de ataque observada (Volexity/Microsoft) y su mapeo a Kill Chain
| # | Fase Kill Chain | Qué hace el atacante | Artefacto | Fuente de log |
|---|---|---|---|---|
| 1 | Reconocimiento | Escaneo masivo de servidores Exchange vulnerables | Requests de prueba a `/autodiscover/` desde IPs externas | IIS |
| 2 | Explotación | CVE-2021-26855: SSRF con cookie `X-AnonResource-Backend` falsificada | URI anómala con `@dominio-externo`, status 200/241, request muy corto (`time-taken` bajo) | IIS |
| 3 | Instalación | CVE-2021-27065: POST a `/ecp/` que escribe el webshell `.aspx` | POST a `/ecp/...` seguido de un GET al archivo recién creado (ej. `/owa/auth/RedirSuiteServiceProxy.aspx`) | IIS |
| 4 | Comando y Control | Ejecución de comandos vía el webshell | Requests repetidos GET/POST al webshell con parámetros codificados en base64 | IIS |
| 4b| Comando y Control (evidencia en host) | El webshell ejecuta comandos del sistema | `w3wp.exe` (proceso de IIS/Exchange) generando `cmd.exe`/`powershell.exe` como hijo (EventCode 4688) | Windows Event Log |
| 5 | Acciones sobre objetivos | Exportación de buzones a `.pst` vía `New-MailboxExportRequest` | Entrada en PowerShell Operational Log (EventID 4103/4104) con el cmdlet | Windows Event Log |
| 5b| Acciones sobre objetivos | Volcado de credenciales (LSASS) antes de exfiltrar | Acceso al proceso `lsass.exe` desde un proceso no estándar (Sysmon EventID 10 equivalente) | Windows Event Log |
| 5c| Acciones sobre objetivos | Descarga del `.pst` exportado vía el webshell (exfiltración) | GET al archivo `.pst` colocado en carpeta web-accesible | IIS |

## Las 5 reglas de detección (mínimo pedido: 4-5)
1. **SSRF / bypass de autenticación** — IIS: URIs con `@` seguido de dominio externo en
   `/autodiscover/` o `/ecp/`, o presencia del header/cookie `X-AnonResource-Backend`.
2. **Escritura de webshell** — IIS: POST a `/ecp/` con status 200 seguido (en <60s) de un GET nuevo
   a un archivo `.aspx` en una ruta de autenticación que antes no existía.
3. **Ejecución de comandos vía webshell (C2)** — Windows Event Log: `w3wp.exe` como proceso padre de
   `cmd.exe` o `powershell.exe`.
4. **Exportación masiva de buzones** — Windows Event Log: cmdlet `New-MailboxExportRequest` en el
   PowerShell Operational Log.
5. **Acceso a LSASS / posible exfiltración de credenciales** — Windows Event Log: proceso no estándar
   (no `lsass.exe`, no herramientas EDR conocidas) accediendo a `lsass.exe`.

Detalle completo de cada regla (lógica SPL) en [`03_guia_splunk.md`](03_guia_splunk.md).

## Fuentes de log (2 requeridas por rúbrica, cumplidas)
1. **IIS logs** (W3C extended format) — tráfico web hacia Exchange (`/autodiscover`, `/ecp`, `/owa`).
2. **Windows Event Logs** (formato `clave=valor`) — creación de procesos, PowerShell operational log,
   accesos a proceso tipo Sysmon.

## División de trabajo (2 personas)
- **Persona 1 (infra/datos)**: cargar los archivos generados en Splunk (`monitor://` o `oneshot`),
  validar que los campos se extraigan correctamente, dejar el ambiente estable y reproducible.
- **Persona 2 (detección/análisis)**: probar y ajustar las 5 búsquedas SPL, armar los dashboards,
  escribir el plan de triage con enriquecimiento en VirusTotal.
- **Ambos**: repasar juntos el análisis técnico completo (Kill Chain, artefactos, plan de respuesta)
  para poder explicarlo indistintamente — esto pesa tanto o más que el puntaje directo.

## Cronograma de 4 días
- **Día 1**: generar y validar los dos datasets → cargarlos en Splunk, confirmar extracción de campos.
  En paralelo, avanzar el documento de análisis técnico (Kill Chain + operación técnica) — no depende
  de que Splunk esté funcionando.
- **Día 2**: las 5 búsquedas SPL guardadas como alertas + 2 dashboards (overview y detalle por fase).
  Terminar la sección de artefactos digitales y equipos que los producen.
- **Día 3**: plan de triage con demo real de VirusTotal sobre un IOC del dataset (IP externa usada en
  el SSRF). Plan de respuesta al incidente. Grabar video de respaldo de la demo completa.
- **Día 4**: armar y ensayar la presentación (15 min cronometrados). Sesión cruzada: cada uno explica
  lo que NO construyó. Preparar respuestas a preguntas trampa previsibles.

## Archivos de este proyecto
- `docs/00_PLAN_MAESTRO.md` — este archivo (fuente de verdad del proyecto)
- `docs/01_kill_chain_artefactos.md` — detalle técnico completo del ataque + artefactos + evidencia
- `docs/02_plan_triage_respuesta.md` — plan de triage y plan de respuesta a incidentes
- `docs/03_guia_splunk.md` — carga de datos en Splunk, lookups de threat intel y las 7 búsquedas SPL
- `scripts/generar_logs.py` — generador de los dos datasets sintéticos (IIS W3C + Windows Event)
- `data/iis_logs.log`, `data/windows_events.log` — datasets sintéticos generados
- `data/sysmon_otrf_real.json` — subconjunto filtrado (28 eventos) del dataset **real** de OTRF
- `splunk/lookups/*.csv` — IOCs reales (IPs, webshells, user-agents) publicados por Splunk para este
  ataque exacto

## Estado final en Splunk (verificado funcionando)
- Índice `proxylogon` con 3 sourcetypes: `iis`, `windows_events_proxylogon` (sintéticos, anclados a
  IOCs reales) y `_json` (28 eventos **reales** de OTRF, ejecución genuina del exploit público).
- 3 lookups reales cargados (`hafnium_ips`, `hafnium_webshells`, `hafnium_useragents`).
- **7 búsquedas guardadas** en Splunk (ver detalle en `docs/03_guia_splunk.md` sección 5):
  1-5 son las reglas de detección por fase del kill chain (con `dedup` para descartar duplicados de
  iteraciones previas de carga de datos), 6 es la validación cruzada contra el dataset real de OTRF,
  7 es la prueba de falsos positivos (verificada en 0).
- 2 dashboards (`ProxyLogon - Overview`, `ProxyLogon - Detalle por Fase`), este último incluye un
  panel final mostrando la validación contra datos reales.
- Cifras finales limpias de cada regla (verificadas 14/07/2026 tras corregir timestamps y duplicados):
  Regla 1 = 7, Regla 2 = 2, Regla 3 = 4, Regla 4 = 1, Regla 5 = 1, Regla 6 = 3, Regla 7 = 0.
- El dataset real de OTRF quedó en su propio sourcetype `json_otrf_real` (con extracción de
  timestamp corregida vía `props.conf` — el sourcetype `_json` original tenía un bug de fecha, ver
  "Incidentes resueltos" abajo). El sourcetype `_json` y `sysmon_otrf_real` con datos antiguos siguen
  huérfanos en el índice pero no los usa ninguna alerta ni dashboard.

## Fuentes externas citables (usar en la presentación y en la ronda de preguntas)
- [CISA AA21-062A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a) — advisory
  oficial con la lista de IOCs de HAFNIUM, fuente de la IP `103.77.192.219` usada en el dataset.
- [Splunk — Detecting HAFNIUM Exchange Server Zero-Day Activity in Splunk](https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html) —
  investigación oficial de Splunk sobre este ataque, con SPL de referencia.
- [github.com/stressboi/hafnium-exchange-splunk-csvs](https://github.com/stressboi/hafnium-exchange-splunk-csvs) —
  IOCs en CSV (IPs, hashes de webshell, nombres de archivo, user-agents) compilados de Volexity,
  Microsoft y Huntress Labs, usados como lookup tables reales en Splunk. `help.aspx` (nuestro
  webshell) y el user-agent `DuckDuckBot` que usamos para camuflar al atacante vienen de aquí.
- [Microsoft Security Blog — HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) —
  fuente primaria del descubrimiento y atribución del ataque.
- [Volexity — Operation Exchange Marauder](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/) —
  primer análisis técnico detallado de la explotación in-the-wild (mencionar si preguntan quién
  descubrió el ataque primero).
- [Microsoft CSS-Exchange — Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/Test-ProxyLogon.ps1) —
  script oficial de Microsoft para detectar IOCs de ProxyLogon; nuestra Regla 2 está alineada con su
  lógica real (búsqueda de `Set-*VirtualDirectory` en logs de ECP).
- [OTRF Security-Datasets — Exchange ProxyLogon SSRF RCE POC](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-210314014019.html) —
  dataset **real** (no sintético) de eventos Sysmon capturados al ejecutar el exploit público de
  ProxyLogon contra un Exchange de laboratorio. Fuente de la Regla 6 (validación cruzada) — la mejor
  respuesta posible a "¿esto es real?".
- [ESET — Exchange servers under siege from at least 10 APT groups](https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/) —
  confirma al sector financiero entre los efectivamente comprometidos en la campaña real, base de la
  elección de Corporación Financiera del Pacífico S.A. como organización hipotética.

## Organización hipotética
Ver `docs/01_kill_chain_artefactos.md` sección 0 — Corporación Financiera del Pacífico S.A. (CFP),
con justificación basada en el reporte de ESET sobre sectores reales afectados por ProxyLogon.
Repasarla para poder explicarla; se retoma en el plan de respuesta (notificación a SBS, Ley 29733).

## Incidente resuelto durante el desarrollo (anécdota útil para la ronda de preguntas)
Al intentar limpiar datos duplicados del índice, un cambio de permisos via API dejó el rol admin de
Splunk sin capacidades por accidente. Se resolvió eliminando el archivo de configuración local
corrupto (`authorize.conf`) y reiniciando Splunk para que cargara los valores de fábrica — sin
pérdida de datos, alertas ni dashboards. Vale la pena mencionarlo si preguntan sobre gestión de
riesgos operativos de un SIEM en producción: los cambios de configuración administrativa deben
probarse con cuidado, y es buena práctica tener un plan de rollback (en este caso, restaurar el
archivo de configuración por defecto).

**Segundo incidente (detectado por el equipo, no solo por mí)**: al revisar el dashboard "Overview"
en la UI, se notó que el gráfico de volumen de tráfico mostraba un rango de fechas de 2021 a 2026,
en vez de solo marzo de 2021. Causa: el dataset real de OTRF se había ingestado con el sourcetype
genérico `_json` de Splunk, que no reconoció automáticamente el campo `TimeCreated` como el
timestamp del evento y usó la hora de carga (2026) en su lugar. Se corrigió creando un sourcetype
dedicado (`json_otrf_real`) con extracción de timestamp explícita vía `props.conf`
(`TIME_PREFIX`/`TIME_FORMAT`), y reingestando el dataset. También se descubrió que las Reglas 6 y 7
no aparecían en la lista de "Alerts" de la UI porque se habían creado como búsquedas simples
(`is_scheduled=0`) en vez de alertas programadas — se corrigió igualándolas a la configuración de las
Reglas 1-5. Buen ejemplo real de por qué siempre hay que verificar en la interfaz, no solo confiar en
que la API respondió 200.

## Preguntas trampa a preparar (Día 4)
- ¿Por qué eligieron estas 5 reglas y no otras?
- ¿Cómo reducen falsos positivos en cada regla?
- ¿Qué pasa si el atacante cambia el nombre o la ruta del webshell?
- ¿Por qué IIS + Windows Event Logs y no, por ejemplo, logs de firewall?
- ¿Cómo se ve esto mapeado en MITRE ATT&CK?
- ¿Qué harían distinto si esto fuera un entorno real en producción?
- ¿Por qué generaron logs sintéticos en vez de usar una VM Exchange vulnerable real? (Respuesta: por
  tiempo y por riesgo de operar una vulnerabilidad crítica real sin aislamiento adecuado; los patrones
  están anclados 1:1 a los reportes públicos del ataque real, y además validamos las reglas contra un
  dataset real de OTRF — Regla 6 — que confirma que detectarían la ejecución genuina del exploit.)
- ¿Por qué CFP y no otro sector? (Respuesta: el sector financiero está confirmado como efectivamente
  afectado en la campaña real, según el reporte de ESET sobre los 10 grupos APT que explotaron
  ProxyLogon — no es una elección arbitraria.)
- ¿Cómo saben que sus reglas detectarían el ataque real y no solo su simulación? (Respuesta: Regla 6 —
  las mismas reglas se probaron contra el dataset real de OTRF, capturado de una ejecución genuina
  del exploit público, y el patrón `w3wp.exe` → `cmd.exe` con `whoami` coincide exactamente.)
