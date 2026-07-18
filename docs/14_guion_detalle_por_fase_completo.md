# Guión Completo — Dashboard "ProxyLogon - Detalle por Fase" (panel por panel, fila por fila)

Este documento recorre el dashboard exactamente en el orden en que lo vas a mostrar en pantalla,
explicando **cada fila de cada panel** — no solo el resumen de la fase. Úsalo leyendo directamente
mientras compartes pantalla.

**Frase de apertura del dashboard:**
> *"Este dashboard recorre las 9 etapas completas del ataque, en el mismo orden en que ocurrieron,
> cada una con su evidencia específica extraída directamente de nuestras dos fuentes de log."*

---

## Panel 1 — Fase 1: Reconocimiento (escaneo externo buscando Exchange vulnerable)

```
_time                c_ip              cs_uri_stem                        sc_status
09:12:00              198.51.100.23     /autodiscover/autodiscover.xml     403
09:12:04              198.51.100.45     /autodiscover/autodiscover.xml     403
09:12:08              198.51.100.91     /autodiscover/autodiscover.xml     403
```

> *"Este es el primer indicio del ataque, 33 minutos antes de la explotación real. Tres direcciones
> IP distintas — .23, .45 y .91, todas del mismo bloque /24 — consultan la misma ruta,
> `/autodiscover/autodiscover.xml`, con solo 4 segundos de diferencia entre cada una. Las tres
> reciben código 403, es decir, acceso denegado — el servidor las rechaza porque no traen ningún
> payload malicioso todavía, es simplemente el atacante verificando que el endpoint existe y
> responde."*

**Por qué esto es reconocimiento y no tráfico normal:**
> *"Ningún usuario legítimo de CFP consulta ese endpoint desde tres IPs externas distintas en una
> ventana de 8 segundos. Este patrón —múltiples IPs, mismo endpoint, ventana de tiempo muy corta— es
> la firma característica de un escaneo automatizado a escala, consistente con la técnica MITRE
> ATT&CK T1595, Escaneo Activo."*

**Nota importante para la ronda de preguntas:**
> *"Este panel no corresponde a ninguna de nuestras 7 alertas — es evidencia adicional que dejamos
> visible en el dashboard para completar la narrativa del Kill Chain, pero no generamos una regla
> de detección dedicada para el reconocimiento porque, por sí solo, un 403 no es un indicador
> confiable de ataque — muchísimo tráfico de internet golpea endpoints públicos y recibe 403 sin
> ninguna intención maliciosa detrás. Lo mostramos como contexto, no como alerta."*

---

## Panel 2 — Fase 2: Explotación — SSRF Autodiscover Bypass (CVE-2021-26855)

```
_time      c_ip             ip_conocida_hafnium  cs_uri_stem                       cs_uri_query                                                                                    sc_status  time_taken
09:45:00   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:45:03   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:45:09   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:45:18   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:45:30   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:45:45   103.77.192.219   TRUE                 /autodiscover/autodiscover.json   @update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net       241        8
09:46:05   103.77.192.219   TRUE                 /ecp/proxyLogon.ecp               (vacío)                                                                                          200        340
```

> *"33 minutos después del reconocimiento, la misma técnica pero ahora con intención real: la
> dirección `103.77.192.219` — que reconocemos inmediatamente por la columna
> `ip_conocida_hafnium=TRUE`, generada automáticamente por nuestro lookup contra 16 IPs reales de
> HAFNIUM — envía 6 peticiones idénticas en 45 segundos."*

**Explicando la URI maliciosa, letra por letra:**
> *"Miren la columna `cs_uri_query`: `@update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/
> autodiscover.json%3F@update-cdn-svc.net`. El símbolo `@` justo después del nombre del endpoint es
> el corazón del exploit — hace que el parser de rutas de Exchange interprete mal dónde termina la
> ruta real y dónde empiezan los parámetros, permitiéndole al atacante inyectar instrucciones de
> enrutamiento hacia el backend interno de Exchange. El resultado es el código de respuesta 241 —
> no es un código HTTP estándar, es un código interno específico de Exchange que indica que la
> petición fue reenviada exitosamente al backend."*

**El dato que más convence a un analista experimentado:**
> *"Fíjense en `time_taken`: 8 milisegundos, en las 6 peticiones, sin variación. Ningún cliente
> humano de Outlook genera una respuesta consistente de 8ms para esta operación — eso es la firma
> de un script automatizado ejecutándose en bucle, no una persona escribiendo en un navegador."*

**La séptima fila — la transición:**
> *"Y aquí está el puente hacia la siguiente fase: a las 09:46:05, la misma IP —ya con el bypass
> logrado— manda un POST a `/ecp/proxyLogon.ecp`. `sc_status=200` y `time_taken=340ms`, mucho más
> lento que las peticiones anteriores. Esto ya no es una consulta, es una operación de escritura —
> entramos a la Fase 3."*

---

## Panel 3 — Fase 3: Instalación — Escritura del Webshell (CVE-2021-27065)

```
_time      c_ip             cs_method  cs_uri_stem              sc_status  time_taken
09:46:05   103.77.192.219   POST       /ecp/proxyLogon.ecp      200        340
09:46:20   103.77.192.219   GET        /owa/auth/help.aspx      200        45
```

> *"Este panel aísla exactamente las dos mitades de la instalación del webshell. La primera fila es
> la misma que cerramos en el panel anterior: el POST que efectivamente escribe el archivo,
> abusando del cmdlet legítimo `Set-OabVirtualDirectory` accesible vía el panel ECP de Exchange. 15
> segundos después, la segunda fila: un GET a `/owa/auth/help.aspx`, respuesta 200 — el atacante
> confirmando que su puerta trasera ya está ahí y es accesible desde internet."*

**Sobre el nombre del archivo, si preguntan:**
> *"`help.aspx` no es un nombre que inventamos nosotros — es uno de 31 nombres de webshell
> documentados realmente en esta campaña, compilados por el equipo de investigación de Splunk a
> partir de reportes de Volexity, Microsoft y Huntress Labs. Otros nombres reales de la misma lista
> incluyen `web.aspx`, `shell.aspx`, `errorEE.aspx`."*

**El argumento forense (repítelo aquí, es tu mejor momento de esta sección):**
> *"CVE-2021-26855, que vimos en el panel anterior, es una vulnerabilidad pre-autenticación. Este
> POST que estamos viendo ahora, CVE-2021-27065, es post-autenticación — bajo condiciones normales
> solo un administrador con sesión válida podría escribir un archivo aquí. El hecho de que una IP
> externa, sin ninguna autenticación previa registrada en nuestros logs, haya logrado ejecutar esta
> escritura, demuestra por sí solo que el SSRF del panel anterior funcionó exitosamente como
> puente."*

---

## Panel 4 — Fase 4: Comando y Control (w3wp.exe genera cmd/powershell)

```
_time      Computer                       NewProcessName                  ParentProcessName                                                           CommandLine
09:46:46   EXCH01.cfp-financiera.local    C:\Windows\System32\cmd.exe     C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe                cmd.exe /c whoami
09:47:41   EXCH01.cfp-financiera.local    C:\Windows\System32\cmd.exe     C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe                cmd.exe /c ipconfig /all
09:49:06   EXCH01.cfp-financiera.local    C:\Windows\System32\cmd.exe     C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe                cmd.exe /c net user
09:51:01   EXCH01.cfp-financiera.local    C:\Windows\System32\powershell.exe  C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe            powershell.exe /c powershell -enc JABjAGwAaQBlAG4AdAA...
```

> *"Este panel ya no viene de los logs de IIS — viene de nuestra segunda fuente, el Windows Event
> Log del servidor `EXCH01.cfp-financiera.local`. En las 4 filas vemos la misma columna
> `ParentProcessName`: `w3wp.exe`, el proceso que ejecuta IIS/Exchange. Que este proceso genere una
> consola de comandos como hijo —columna `NewProcessName`— es estructuralmente imposible en
> operación normal de un servidor Exchange."*

**Explicando cada comando, en orden:**
> *"09:46:46, `whoami` — lo primero que hace cualquier atacante al lograr ejecución: verificar con
> qué privilegios está corriendo. 09:47:41, `ipconfig /all` — reconocimiento de la topología de red
> interna de CFP. 09:49:06, `net user` — enumeración de cuentas locales, buscando objetivos para
> movimiento lateral. Y 09:51:01, el más avanzado: PowerShell con el flag `-enc`, que ejecuta un
> comando codificado en Base64 — miren que el `CommandLine` no muestra el comando real, muestra la
> cadena codificada `JABjAGwAaQBlAG4AdAA...` — es una técnica de evasión documentada, dificulta que
> una inspección superficial identifique la intención real sin decodificarlo primero."*

---

## Panel 5a — Fase 5a: Exportación de Buzón (New-MailboxExportRequest)

```
_time      Computer                       ScriptBlockText
09:52:00   EXCH01.cfp-financiera.local    New-MailboxExportRequest -Mailbox 'jgarcia' -FilePath '\\EXCH01\C$\inetpub\wwwroot\aspnet_client\backup.pst'
```

> *"Este evento viene del PowerShell Script Block Log de Windows, que captura el contenido completo
> del script ejecutado, no solo que se corrió PowerShell. `New-MailboxExportRequest` es un cmdlet
> 100% legítimo de Exchange Management Shell, normalmente usado por administradores para exportar
> buzones a un archivo `.pst` con fines de migración o respaldo. El atacante lo abusa para exportar
> el buzón completo del usuario `jgarcia` — pero miren el `-FilePath`: no apunta a un recurso de red
> interno controlado por TI, apunta a `\inetpub\wwwroot\aspnet_client\`, es decir, dentro de la
> carpeta raíz web pública del servidor. Convierte un archivo interno en algo descargable
> remotamente por HTTP — esa es la firma de que esta no es una operación administrativa legítima."*

---

## Panel 5b — Fase 5b: Acceso a LSASS (volcado de credenciales)

```
_time      Computer                       SourceProcessName                TargetProcessName                  GrantedAccess
09:53:30   EXCH01.cfp-financiera.local    C:\Windows\Temp\procdump.exe     C:\Windows\System32\lsass.exe       0x1410
```

> *"90 segundos después de la exportación del buzón, el atacante va por credenciales. `procdump.exe`
> es una herramienta 100% legítima de Sysinternals — de Microsoft — normalmente usada por
> administradores para diagnóstico de memoria de aplicaciones. Miren dos cosas: primero, la ruta,
> `C:\Windows\Temp\` — no es donde normalmente residiría una herramienta administrativa instalada
> intencionalmente, es la carpeta temporal, consistente con un binario subido por el atacante a
> través del webshell. Segundo, el objetivo: `lsass.exe`, el proceso de Windows que mantiene en
> memoria las credenciales de los usuarios con sesión iniciada. `GrantedAccess=0x1410` es el valor
> hexadecimal de los permisos obtenidos, que incluye lectura de memoria — necesario para extraer
> esas credenciales. Esta es la técnica MITRE ATT&CK T1003.001, Volcado de Credenciales del Sistema
> Operativo desde la memoria de LSASS."*

---

## Panel 5c — Fase 5c: Exfiltración (descarga del .pst vía webshell)

```
_time      c_ip             cs_method  cs_uri_stem                  sc_status  time_taken
09:54:15   103.77.192.219   GET        /aspnet_client/backup.pst   200        5200
```

> *"El cierre del ataque. La misma IP del atacante descarga el archivo que se exportó en el Panel
> 5a. Miren el `time_taken`: 5200 milisegundos — más de 600 veces más lento que las peticiones de
> explotación inicial (8ms). Eso es exactamente lo que esperaríamos de la transferencia de un
> archivo de tamaño considerable, no de una simple consulta. Con esta fila, confirmamos que la
> exfiltración se completó con éxito."*

---

## Panel 6 — Línea de Tiempo Completa del Ataque

```
_time      evento                                    sourcetype  c_ip
09:12:00   1. Reconocimiento (escaneo externo)        iis         198.51.100.23
09:12:04   1. Reconocimiento (escaneo externo)        iis         198.51.100.45
09:12:08   1. Reconocimiento (escaneo externo)        iis         198.51.100.91
09:45:00   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:45:03   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:45:09   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:45:18   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:45:30   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:45:45   2. SSRF Autodiscover (explotación)          iis         103.77.192.219
09:46:05   3. Escritura webshell (POST /ecp/)          iis         103.77.192.219
           ... continúa con 3b (acceso GET), 4 (comandos), 5a (export), 5b (LSASS), 5c (exfiltración) ...
```

> *"Este panel final consolida todo lo que acabamos de ver, de ambas fuentes de log, en una sola
> tabla ordenada cronológicamente. La columna `evento` está etiquetada con el número de fase
> correspondiente — así se ve, en una sola mirada, la progresión completa: desde el primer escaneo a
> las 09:12, pasando por la explotación a las 09:45, hasta la exfiltración confirmada a las 09:54.
> **42 minutos y 15 segundos de principio a fin.** Y recuerden: nuestra primera alerta se hubiera
> disparado a las 09:45:05 — es decir, 9 minutos antes de que el atacante lograra exfiltrar
> cualquier dato. Esa es la ventana real de contención que este SIEM le daría a un analista de
> CFP."*

---

## Panel 7 — Validación Cruzada: Ejecución REAL del Exploit (dataset público OTRF)

```
TimeCreated              Hostname                   Image                                                          ParentImage                          CommandLine
2021-03-14T01:40:15.274Z MXS01.azsentinel.local     C:\Windows\...\v4.0.30319\cvtres.exe                          C:\Windows\System32\inetsrv\w3wp.exe  cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:...\RES37C9.tmp" "...\RES37C8.tmp"
2021-03-14T01:40:15.342Z MXS01.azsentinel.local     C:\Windows\System32\cmd.exe                                    C:\Windows\System32\inetsrv\w3wp.exe  cmd /c whoami
2021-03-14T01:40:15.347Z MXS01.azsentinel.local     C:\Windows\System32\cmd.exe                                    C:\Windows\System32\inetsrv\w3wp.exe  cmd /c whoami
```

**Este es tu momento más fuerte de todo el dashboard — cambia el tono aquí:**
> *"Este último panel no es parte de nuestra simulación de CFP. Fíjense en la fecha:
> **2021-03-14**, no 2026. Este es un dataset público, real, publicado por OTRF —Open Threat
> Research Forge—, un equipo de investigación de amenazas reconocido en la comunidad de
> ciberseguridad. Son eventos Sysmon capturados literalmente al ejecutar el exploit público de
> ProxyLogon contra un servidor Exchange de laboratorio real, con hostname
> `MXS01.azsentinel.local`."*

**La comparación que cierra el argumento:**
> *"Miren la columna `ParentImage`: `w3wp.exe`. Y el `CommandLine` de la segunda y tercera fila:
> `cmd /c whoami` — exactamente el mismo comando, generado por el mismo proceso padre, que
> mostramos en nuestro Panel 4 de esta misma dashboard. No es una coincidencia de diseño: es la
> prueba de que el patrón de detección que construimos —`w3wp.exe` generando una shell— no solo
> funciona contra nuestra simulación, funcionaría exactamente igual contra una ejecución genuina y
> documentada del ataque real."*

---

## Resumen de cifras exactas para tener a mano (por si preguntan un número específico)

| Panel/Fase | Filas | Fuente |
|---|---|---|
| Fase 1 — Reconocimiento | 3 | IIS |
| Fase 2 — Explotación (SSRF) | 7 | IIS |
| Fase 3 — Instalación (webshell) | 2 | IIS |
| Fase 4 — Comando y Control | 4 | Windows Event Log |
| Fase 5a — Exportación de buzón | 1 | Windows Event Log |
| Fase 5b — Acceso a LSASS | 1 | Windows Event Log |
| Fase 5c — Exfiltración | 1 | IIS |
| Validación OTRF (real) | 3 | Dataset externo OTRF |
| **Duración total del ataque** | — | 09:12:00 → 09:54:15 = **42 min 15 seg** |
