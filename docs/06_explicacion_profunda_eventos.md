# Explicación profunda — cada IOC, cada campo, cada evento

Este documento explica literalmente **todo lo que vas a mostrar en pantalla**, para que puedas
leerlo o parafrasearlo en vivo durante la sustentación virtual. Está organizado exactamente en el
orden en que aparecen las 7 alertas. Todos los datos fueron verificados en Splunk momentos antes de
escribir esto — son los que vas a ver tú mismo en pantalla.

---

## Glosario de IOCs (Indicadores de Compromiso) — apréndete esto primero

| Elemento | Valor | Qué es | Por qué importa |
|---|---|---|---|
| IP atacante | `103.77.192.219` | Dirección IP pública desde la que se origina todo el ataque | Es un IOC **real**, documentado en el advisory oficial [CISA AA21-062A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a) y en la lista de IPs de HAFNIUM que publicó Volexity/Microsoft/Huntress Labs. No la inventamos. |
| Dominio C2 | `update-cdn-svc.net` | Dominio ficticio usado en el payload del ataque | Simula el dominio "externo" que el atacante pone en la URI manipulada para el bypass SSRF |
| Servidor víctima (IP interna) | `10.10.20.15` | Dirección IP interna del servidor Exchange de CFP | Es el `s-ip` (server IP) en los logs de IIS — el servidor que recibe el ataque |
| Servidor víctima (hostname) | `EXCH01.cfp-financiera.local` | Nombre del servidor Exchange dentro del dominio de CFP | Aparece en los logs de Windows Event Log como campo `Computer` |
| Webshell | `help.aspx` | Nombre del archivo malicioso que el atacante deja en el servidor | Es uno de los **31 nombres reales de webshell** documentados públicamente para esta campaña (repositorio `stressboi/hafnium-exchange-splunk-csvs`), no inventado |
| IPs de reconocimiento | `198.51.100.23`, `.45`, `.91` | 3 IPs distintas que escanean el servidor antes del ataque real | Representan el paso de reconocimiento — son direcciones del rango reservado TEST-NET-2 (RFC 5737), seguras para usar en una demo |
| IPs internas benignas | `192.168.1.45` a `192.168.1.117` (8 IPs) | Empleados legítimos de CFP usando OWA/Outlook normalmente | Es el "ruido de fondo" — tráfico normal mezclado con el ataque para que el triage tenga sentido real |
| Organización hipotética | Corporación Financiera del Pacífico S.A. (CFP) | Entidad financiera peruana ficticia, 850 empleados, 30 agencias | El "cliente" de nuestro SOC en este ejercicio |

---

## Cómo leer una fila de log de IIS (esto te lo van a preguntar)

Formato W3C Extended Log (el formato nativo real de IIS), ejemplo de una fila real:
```
2026-07-16 09:45:00 10.10.20.15 GET /autodiscover/autodiscover.json @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net 443 - 103.77.192.219 DuckDuckBot/1.0... 241 0 0 8
```
Campos, en orden: **fecha, hora, IP del servidor (s-ip), método HTTP (cs-method), ruta solicitada
(cs-uri-stem), parámetros de la URL (cs-uri-query), puerto (443), usuario autenticado (`-` = ninguno),
IP del cliente/atacante (c-ip), user-agent, código de estado HTTP (sc-status), sub-estado, código
Win32, tiempo de respuesta en milisegundos (time-taken)**.

---

## Regla 1 — SSRF Autodiscover Bypass (Fase: Explotación, CVE-2021-26855)

### La búsqueda SPL, explicada línea por línea
```spl
index=proxylogon sourcetype=iis
(cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*" OR cs_Cookie="*X-BEResource*")
| lookup hafnium_ips src_ip AS c_ip OUTPUT isBad AS ip_conocida_hafnium
| table _time c_ip ip_conocida_hafnium cs_uri_stem cs_uri_query sc_status time_taken
| sort _time
```
- **Línea 1**: busca en el índice `proxylogon`, solo en los logs de tipo `iis` (nuestra primera
  fuente de log, la de red/perímetro).
- **Línea 2**: filtra a peticiones cuya ruta contiene `autodiscover` (el servicio de
  autoconfiguración de Outlook) o `/ecp/` (el panel de administración de Exchange).
- **Línea 3**: de esas, se queda solo con las que tienen `@` en los parámetros de la URL (el patrón
  de bypass SSRF) **o** traen las cookies internas de Exchange (`X-AnonResource-Backend`,
  `X-BEResource`) que nunca deberían venir de un cliente externo.
- **Línea 4 (`lookup`)**: cruza automáticamente la IP de origen contra nuestra tabla de 16 IPs reales
  de HAFNIUM. Si hace match, agrega la columna `ip_conocida_hafnium=TRUE`.
- **Líneas 5-6**: arma la tabla final ordenada por tiempo.

### Los 7 resultados, explicados uno por uno

**Filas 1 a 6** (09:45:00 a 09:45:45, cada ~15-18 segundos): 6 peticiones idénticas —
```
GET /autodiscover/autodiscover.json?@update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net
```
- **Qué es esto técnicamente**: el atacante manda una URL donde, después de `autodiscover.json`, pone
  `@update-cdn-svc.net`. Exchange interpreta mal esta sintaxis y termina reenviando la petición hacia
  su **propio backend interno** creyendo que viene de un componente de confianza — esto es el "server
  side request forgery" (SSRF): el servidor termina haciéndose una petición a sí mismo en nombre del
  atacante.
- **`sc_status=241`**: un código de estado HTTP no estándar (Exchange lo usa internamente) que indica
  que la petición fue reenviada al backend — evidencia de que el bypass funcionó.
- **`time_taken=8`** (milisegundos): extremadamente rápido. Un humano usando Outlook real jamás genera
  una respuesta en 8ms para esta operación — es la firma de un **script automatizado**, no una
  persona.
- **Por qué se repite 6 veces**: en el ataque real documentado, el atacante manda varias peticiones
  seguidas porque el SSRF no siempre funciona a la primera (depende del estado interno del servidor)
  — repetirlo aumenta la probabilidad de éxito.

**Fila 7** (09:46:05): `POST /ecp/proxyLogon.ecp`, `sc_status=200`, `time_taken=340`.
- Esta ya es la **transición hacia la Regla 2** — el atacante, ya con el bypass logrado, manda un
  POST al panel de administración (`/ecp/`) para iniciar la escritura del webshell. La incluimos
  aquí porque también cae dentro del patrón de búsqueda de la Regla 1 (contiene `/ecp/`), pero
  conceptualmente marca el final de la fase de explotación y el inicio de la instalación.

### El dato `ip_conocida_hafnium=TRUE`
En las 7 filas aparece `TRUE`. Esto significa que Splunk cruzó `103.77.192.219` contra la tabla
`hafnium_ips.csv` (cargada como lookup) y la encontró — es **la primera IP de la lista** que Splunk
mismo publicó como IOC real de esta campaña. Si dijera `FALSE` o quedara vacío, significaría que la
IP no está en ninguna lista de amenazas conocidas — ahí es donde entra el análisis manual con
VirusTotal como respaldo.

---

## Regla 2 — Webshell Drop (Fase: Instalación, CVE-2021-27065)

### La búsqueda SPL
```spl
index=proxylogon sourcetype=iis
((cs_uri_stem="/ecp/proxyLogon.ecp" cs_method=POST) OR (cs_uri_stem="/owa/auth/help.aspx" cs_method=GET))
| table _time c_ip cs_method cs_uri_stem sc_status time_taken
| sort _time
```
Busca exactamente 2 tipos de eventos: el POST que escribe el webshell, y el GET que confirma que
quedó accesible. Es una búsqueda "determinística" — no usa comodines amplios, apunta directo a las
2 rutas exactas que sabemos que están involucradas.

### Los 2 resultados, explicados

**Fila 1** (09:46:05): `POST /ecp/proxyLogon.ecp`, `sc_status=200`, `time_taken=340`.
- El atacante, ya autenticado gracias al SSRF de la Regla 1, manda un POST al endpoint
  `proxyLogon.ecp` (de aquí viene el nombre "ProxyLogon" de toda la vulnerabilidad). Este endpoint
  permite, mediante un abuso de la función `Set-OabVirtualDirectory` de Exchange, escribir un
  archivo arbitrario en el disco del servidor.
- **`time_taken=340`ms**: notablemente más lento que las peticiones de reconocimiento — tiene sentido,
  porque el servidor está efectivamente escribiendo un archivo nuevo en disco, no solo respondiendo
  una consulta.
- **Artefacto correspondiente en Windows**: este mismo momento genera un evento `EventCode=4663`
  (acceso a objeto) donde `w3wp.exe` (el proceso de IIS) escribe el archivo
  `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\help.aspx`.

**Fila 2** (09:46:20, 15 segundos después): `GET /owa/auth/help.aspx`, `sc_status=200`,
`time_taken=45`.
- El atacante confirma que el webshell quedó accesible haciendo un simple GET a la ruta donde lo
  escribió. Respuesta 200 = el archivo existe y es accesible desde internet.
- **Por qué el nombre `help.aspx`**: no lo inventamos — es uno de los 31 nombres de archivo
  documentados realmente en la campaña HAFNIUM (junto con otros como `web.aspx`, `shell.aspx`,
  `errorEE.aspx`), publicados en un repositorio compilado por Splunk a partir de reportes de
  Volexity, Microsoft y Huntress Labs.

---

## Regla 3 — C2 vía Webshell (Fase: Comando y Control)

### La búsqueda SPL
```spl
index=proxylogon sourcetype=windows_events_proxylogon
EventCode=4688 ParentProcessName="*w3wp.exe*"
| table _time Computer NewProcessName ParentProcessName CommandLine
| sort _time
```
Esta es nuestra **segunda fuente de log** — Windows Event Log, no IIS. `EventCode=4688` es el
identificador estándar de Windows para "se creó un nuevo proceso". Filtramos a los casos donde el
proceso **padre** sea `w3wp.exe` (el proceso que ejecuta IIS/Exchange).

### Los 4 resultados, explicados uno por uno

Todos comparten: `Computer=EXCH01.cfp-financiera.local`, `ParentProcessName=...\w3wp.exe`.

1. **09:46:46** — `NewProcessName=cmd.exe`, `CommandLine="cmd.exe /c whoami"`.
   El primer comando que ejecuta el atacante vía el webshell: `whoami` — el comando más básico de
   reconocimiento, para saber con qué usuario/privilegios está corriendo el proceso comprometido.

2. **09:47:41** — `NewProcessName=cmd.exe`, `CommandLine="cmd.exe /c ipconfig /all"`.
   Segundo comando: `ipconfig /all` — reconocimiento de red, para entender la topología interna
   (direcciones IP, DNS, dominio) desde dentro del servidor comprometido.

3. **09:49:06** — `NewProcessName=cmd.exe`, `CommandLine="cmd.exe /c net user"`.
   Tercer comando: `net user` — enumera las cuentas de usuario locales del servidor, buscando
   posibles objetivos para movimiento lateral o escalamiento de privilegios.

4. **09:51:01** — `NewProcessName=powershell.exe`,
   `CommandLine="powershell.exe /c powershell -enc JABjAGwAaQBlAG4AdAA..."`.
   El comando más avanzado: PowerShell con el flag `-enc` (encoded), que ejecuta un comando en
   **Base64**. Esta es una técnica de evasión muy común — el texto en claro del comando no aparece
   directamente en el log, dificultando la detección basada solo en palabras clave. Es la evidencia
   de que el atacante pasó de reconocimiento básico a actividad más sofisticada (probablemente
   estableciendo un canal de comunicación más persistente).

### Por qué esto es la "prueba" definitiva del compromiso
`w3wp.exe` es el proceso que sirve páginas web de Exchange — **jamás**, en operación normal, debería
generar una shell interactiva (`cmd.exe` o `powershell.exe`) como proceso hijo. Cuando esto ocurre,
es la señal más inequívoca de que un webshell está ejecutando comandos arbitrarios del sistema
operativo a través del servidor web.

---

## Regla 4 — Exportación de Buzón (Fase: Acciones sobre los objetivos)

### La búsqueda SPL
```spl
index=proxylogon sourcetype=windows_events_proxylogon
EventCode=4104 ScriptBlockText="*New-MailboxExportRequest*"
| table _time Computer ScriptBlockText
```
`EventCode=4104` corresponde al **PowerShell Script Block Logging** — Windows registra el contenido
completo de los scripts de PowerShell que se ejecutan, no solo que se ejecutó PowerShell.

### El único resultado, explicado
**09:52:00** — 
```
New-MailboxExportRequest -Mailbox 'jgarcia' -FilePath '\\EXCH01\C$\inetpub\wwwroot\aspnet_client\backup.pst'
```
- `New-MailboxExportRequest` es un **cmdlet legítimo** de Exchange Management Shell, diseñado para
  que administradores exporten buzones completos a un archivo `.pst` (formato de Outlook) — por
  ejemplo, para migraciones o respaldos.
- El atacante lo abusa para exportar el buzón completo del usuario `jgarcia` hacia
  `C:\inetpub\wwwroot\aspnet_client\backup.pst` — **una carpeta dentro de la raíz web de IIS**, es
  decir, un lugar accesible directamente por HTTP desde internet. Este es el paso que prepara la
  exfiltración: el atacante convierte un archivo interno en algo descargable remotamente.
- **Por qué es sospechoso y no una operación de TI legítima**: una exportación de buzón real de un
  administrador jamás se guarda dentro de la carpeta pública del servidor web — se guarda en un
  recurso de red interno controlado. Guardar el `.pst` en `aspnet_client` (una ruta típica de
  archivos estáticos de ASP.NET) es la firma de alguien que necesita descargarlo después vía HTTP,
  no de un proceso administrativo normal.

---

## Regla 5 — Acceso a LSASS (Fase: Acciones sobre los objetivos — robo de credenciales)

### La búsqueda SPL
```spl
index=proxylogon sourcetype=windows_events_proxylogon
EventCode=10 TargetProcessName="*lsass.exe*"
NOT SourceProcessName IN ("*MsMpEng.exe*", "*procexp*", "*Taskmgr.exe*")
| table _time Computer SourceProcessName TargetProcessName GrantedAccess
```
`EventCode=10` (estilo Sysmon "ProcessAccess") registra cuando un proceso abre un handle de acceso a
la memoria de otro proceso. `lsass.exe` (Local Security Authority Subsystem Service) es el proceso
de Windows que guarda en memoria las credenciales de los usuarios que iniciaron sesión — es **el**
objetivo clásico para robo de contraseñas. La cláusula `NOT ... IN (...)` excluye procesos legítimos
que normalmente acceden a LSASS (el antivirus de Windows Defender, el Process Explorer, el
Administrador de Tareas) para reducir falsos positivos.

### El único resultado, explicado
**09:53:30** — `SourceProcessName=C:\Windows\Temp\procdump.exe`,
`TargetProcessName=C:\Windows\System32\lsass.exe`, `GrantedAccess=0x1410`.
- `procdump.exe` es una **herramienta legítima de Sysinternals** (de Microsoft), normalmente usada
  por administradores para generar volcados de memoria de procesos con fines de diagnóstico. El
  atacante la abusa (técnica llamada "living off the land": usar herramientas legítimas del propio
  sistema para actividad maliciosa) para volcar la memoria de `lsass.exe` y extraer credenciales.
- **Ubicación sospechosa**: `C:\Windows\Temp\` — no es donde normalmente vive una herramienta
  administrativa instalada; es la carpeta temporal, típica de un binario subido por el atacante a
  través del webshell.
- **`GrantedAccess=0x1410`**: el valor hexadecimal de los permisos otorgados al abrir el proceso
  LSASS — específicamente incluye permiso de **lectura de memoria** (`PROCESS_VM_READ`), necesario
  para extraer el contenido donde viven las credenciales.
- **Técnica MITRE ATT&CK**: T1003.001 (OS Credential Dumping: LSASS Memory) — una de las técnicas
  más documentadas y buscadas en cualquier SOC real.

---

## Regla 6 — Validación con Dataset Real de OTRF

### La búsqueda SPL
```spl
index=proxylogon sourcetype=json_otrf_real
EventID=1 ParentImage="*w3wp*"
| table TimeCreated Hostname Image ParentImage CommandLine
| sort TimeCreated
```
**Diferencia clave con las 5 reglas anteriores**: el `sourcetype=json_otrf_real` **no es nuestro
dataset sintético** — son 28 eventos Sysmon **reales**, capturados por el equipo de investigación
OTRF (Open Threat Research Forge) al ejecutar el exploit público de ProxyLogon contra un servidor
Exchange de laboratorio real, el 14 de marzo de 2021. `EventID=1` es el identificador de Sysmon para
"creación de proceso" (equivalente al `EventCode=4688` de Windows nativo que usamos en la Regla 3).

### Los 3 resultados, explicados

1. **2021-03-14T01:40:15.274Z** — `Image=cvtres.exe`, `ParentImage=...\inetsrv\w3wp.exe`.
   `cvtres.exe` es una utilidad de compilación de .NET — aparece porque, en el ataque real, parte
   de la técnica de ejecución involucra compilar código sobre la marcha (una variante técnica algo
   distinta a la nuestra, pero con el mismo padre sospechoso).

2. y 3. **2021-03-14T01:40:15.342Z y .347Z** — `Image=cmd.exe`, `CommandLine="cmd /c whoami"`
   (2 veces, con 5 milisegundos de diferencia).
   **Este es el hallazgo clave**: el mismísimo comando `whoami`, generado por `w3wp.exe`, en una
   ejecución **real y verificada** del exploit — el patrón idéntico al que representamos en nuestra
   Regla 3. `Hostname=MXS01.azsentinel.local` es el nombre del servidor de laboratorio real donde
   OTRF ejecutó la prueba.

### Por qué mostrar esto vale más que las otras 5 reglas juntas
No es una simulación adicional — es la prueba de que **el mismo patrón de detección (proceso padre
`w3wp.exe` generando una shell) sirve tanto para nuestro escenario hipotético como para una
ejecución genuina, documentada y pública del ataque real.** Si el profesor pregunta "¿cómo saben que
esto funcionaría contra el ataque real?", la respuesta es literalmente esta regla.

---

## Regla 7 — Prueba de Falsos Positivos

### La búsqueda SPL
```spl
index=proxylogon sourcetype=iis c_ip="192.168.1.*"
(cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*" OR cs_Cookie="*X-BEResource*")
| stats count as falsos_positivos_regla1
```
Es **exactamente la misma lógica de detección de la Regla 1**, pero forzando el filtro a
`c_ip="192.168.1.*"` — es decir, solo direcciones IP internas de la red de CFP (los empleados
legítimos). Si algún empleado real generara accidentalmente un patrón parecido al del ataque, esta
búsqueda lo mostraría.

### El resultado
`falsos_positivos_regla1 = 0`.

**Qué significa exactamente**: de los ~280 eventos de tráfico interno benigno que generamos (logins
normales a OWA, consultas de Outlook, sincronización de ActiveSync), **ninguno** coincide con el
patrón de la Regla 1. Es la evidencia cuantitativa — no solo la afirmación — de que la regla no
genera ruido con actividad normal. Esto responde directamente a la instrucción que el profesor dio
en la aprobación de la propuesta: *"no olvidar considerar los pasos a seguir para triage de la
alerta y confirmar que no es un Falso Positivo."*

---

## La línea de tiempo completa — narrativa de los 42 minutos del ataque

| Hora (2026-07-16) | Fase | Qué pasó |
|---|---|---|
| 09:12:00 - 09:12:08 | 1. Reconocimiento | 3 IPs distintas (`198.51.100.23/45/91`) escanean `/autodiscover/autodiscover.xml`, reciben `403` (rechazadas) — es el sondeo previo, buscando servidores Exchange expuestos |
| 09:45:00 - 09:45:45 | 2. Explotación | 6 peticiones SSRF desde `103.77.192.219`, bypass exitoso (código 241) |
| 09:46:05 | 3. Instalación (parte 1) | POST que escribe el webshell `help.aspx` |
| 09:46:20 | 3. Instalación (parte 2) | GET que confirma que el webshell es accesible |
| 09:46:46 - 09:51:01 | 4. Comando y Control | 4 comandos ejecutados vía el webshell (`whoami`, `ipconfig`, `net user`, PowerShell codificado) |
| 09:52:00 | 5a. Exfiltración (preparación) | Exportación del buzón de `jgarcia` a un `.pst` en carpeta pública |
| 09:53:30 | 5b. Robo de credenciales | `procdump.exe` accede a la memoria de `lsass.exe` |
| 09:54:15 | 5c. Exfiltración (ejecución) | Descarga del `.pst` (`GET /aspnet_client/backup.pst`, 5200ms — transferencia grande) |

**Frase para cerrar esta parte**: "Desde el primer escaneo hasta la exfiltración completa,
el ataque tomó 42 minutos. Nuestra alerta de SSRF se hubiera disparado en el Splunk del SOC de CFP
a las 09:45:00 — es decir, 9 minutos antes de que el atacante lograra exfiltrar cualquier dato. Ahí
está la ventana real de contención."
