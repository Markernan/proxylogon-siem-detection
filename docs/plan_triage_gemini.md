REPORTE DE PROYECTO: ANÁLISIS TÉCNICO, SISTEMA DE DETECCIÓN SIEM Y PLAN DE TRIAJE ANTE INTRUSIÓN PROXYLOGON
Curso: Seguridad de la Información / Ciberseguridad
Caso de Estudio: Explotación de Vulnerabilidades ProxyLogon (Microsoft Exchange) en Entorno Financiero
Entidad Afectada (Caso de Simulación): Corporación Financiera del Pacífico S.A. (CFP)
Plataforma de Simulación: Splunk SIEM Enterprise (Entorno de Laboratorio)
Autores: Alexander Abrisqueta y equipo
1. INTRODUCCIÓN Y RESUMEN EJECUTIVO
El presente documento detalla el análisis técnico, la estrategia de detección en SIEM y el plan de respuesta y triaje del incidente de ciberseguridad derivado de la explotación de ProxyLogon. Este ataque compromete servidores de correo locales Microsoft Exchange mediante el encadenamiento de múltiples vulnerabilidades de día cero (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 y CVE-2021-27065).
Para este proyecto de curso, se simula un escenario de compromiso real en la Corporación Financiera del Pacífico S.A. (CFP), una organización regulada de alta criticidad en el sistema financiero. El adversario (asociado conceptualmente al grupo APT Hafnium) logra evadir los controles perimetrales iniciales, desplegar puertas traseras (webshells), ejecutar comandos remotos, extraer credenciales administrativas del proceso LSASS y comprometer buzones de correo corporativo que contienen información financiera sensible.
Para la detección, se ha configurado un entorno en Splunk SIEM, ingestado con logs reales de red (Servidor Web IIS) y de endpoint (Microsoft Sysmon y Logs de Eventos de Windows), correlacionando alertas específicas por fases y consolidando la información en tableros de control (dashboards) interactivos para facilitar el monitoreo del SOC. Asimismo, se define un Plan de Triaje exhaustivo bajo la metodología SANS/NIST, asegurando el cumplimiento de la normativa local de ciberseguridad financiera.
2. ANÁLISIS TÉCNICO Y LÓGICO DEL ATAQUE (CYBER KILL CHAIN)
Para comprender el flujo del ataque perpetrado por el adversario, se desglosa su comportamiento utilizando el marco de referencia Cyber Kill Chain:
[Reconocimiento] ──> [Explotación (SSRF)] ──> [Instalación (Webshell)] ──> [Comando y Control] ──> [Acciones sobre Objetivos]
     Escaneo            Bypass de Autenticación         Escritura de .aspx             Ejecución de cmd.exe        Exfiltración y LSASS


A. Reconocimiento y Weaponización
El atacante escanea puertos expuestos a Internet buscando servidores Microsoft Exchange que ejecuten servicios OWA (Outlook Web App) desactualizados. Desarrolla o adquiere un exploit capaz de abusar del servicio de autodescubrimiento (Autodiscover).
B. Entrega y Explotación (CVE-2021-26855 - SSRF)
El vector de entrada es una vulnerabilidad de falsificación de petición del lado del servidor (SSRF). El atacante envía una petición HTTP maliciosa especialmente diseñada al endpoint /autodiscover/autodiscover.xml. Al explotar esta falla, el atacante logra autenticarse como el usuario de sistema  en el servidor Exchange sin necesidad de credenciales legítimas.
C. Instalación / Persistencia (CVE-2021-26858 / CVE-2021-27065 - Webshell Drop)
Una vez autenticado con privilegios del sistema, el atacante abusa del servicio de libreta de direcciones o configuraciones de buzón de Exchange para forzar la escritura de un archivo en el disco del servidor. Escribe archivos de código de servidor web (.aspx) maliciosos (comúnmente conocidos como webshells) en directorios públicos de IIS, tales como:
C:\inetpub\wwwroot\aspnet_client\system_web\
D. Comando y Control - C2 (Ejecución de Comandos)
Con la webshell instalada, el atacante realiza peticiones HTTP directas hacia el archivo .aspx recién creado. El proceso de IIS (w3wp.exe) interpreta el código de la webshell y ejecuta comandos a nivel de sistema operativo levantando subprocesos como cmd.exe o powershell.exe. El atacante utiliza herramientas de reconocimiento local como whoami, net user, o descargas de utilidades externas para consolidar su canal de comunicación.
E. Acciones sobre los Objetivos (Robo de Información y Credenciales)
Robo de Credenciales: El atacante ejecuta volcados de memoria de LSASS (Local Security Authority Subsystem Service) para extraer las credenciales en texto claro o los hashes de contraseñas de los usuarios autenticados en el servidor Exchange.
Exfiltración de Datos: Mediante la ejecución de cmdlets de PowerShell propios de Exchange, como New-MailboxExportRequest, el atacante exporta el contenido completo de buzones de correo específicos hacia directorios accesibles vía web para su posterior descarga ilegal.
3. ESTRATEGIA DE DETECCIÓN EN SIEM SPLUNK
La estrategia se basa en la correlación de datos procedentes de dos fuentes principales de información (detección multiorigen), permitiendo visibilidad de red y endpoint:
Servidor Web IIS (Logs de Red W3C): Registra las solicitudes HTTP perimetrales entrantes que acceden al servidor de correo, capturando parámetros críticos como URIs, direcciones IP de origen, agentes de usuario, métodos de petición (POST/GET) y códigos de estado (200, 302, 400).
Microsoft Sysmon / Windows Event Logs (Logs de Endpoint): Monitorea la actividad interna de los procesos del sistema, creación de archivos nuevos en disco (Event ID 11), intentos de lectura a memoria de procesos sensibles (Event ID 10) y la ejecución de comandos de consola (Event ID 1).
Las 7 Alertas Calibradas en Splunk
Para detectar cada etapa del ataque de manera precisa y evitar el ruido operativo en el SOC, se implementaron 7 alertas dentro de la aplicación de Splunk:
ID de Alerta
Nombre de la Alerta
Comportamiento Detectado (Lógica SPL)
Resultados Esperados (Dataset)
01
SSRF Autodiscover Bypass
Peticiones HTTP a /autodiscover/ que contienen patrones de bypass sospechosos y cruzados con lookups de IOCs conocidos.
7 filas
02
Webshell Drop
Creación de archivos con extensión .aspx en directorios web de Exchange ejecutada por los procesos w3wp.exe o UMWorkerProcess.exe.
2 filas
03
C2 via Webshell
Procesos de línea de comandos (cmd.exe o powershell.exe) que tienen como proceso padre al servidor web de IIS (w3wp.exe).
4 filas
04
Mailbox Export
Comandos de consola de Windows que involucran la solicitud de exportación de buzones de correo (New-MailboxExportRequest).
1 fila
05
LSASS Access
Acceso anómalo a la memoria de lsass.exe ejecutado por un proceso no autorizado (comportamiento típico de Mimikatz).
1 fila
06
Validación OTRF
Regla de verificación cruzada para validar las firmas del ataque contra el dataset forense real de la comunidad OTRF.
3 filas
07
Prueba de Falsos Positivos
Regla de control diseñada para calibrar la correlación de IPs conocidas y asegurar un indicador de ruido igual a cero.
0 filas

4. PLAN DE TRIAJE Y CONFIRMACIÓN DEL ATAQUE (SOC L1/L2)
El plan de triaje se ha estructurado bajo un flujo metodológico de escalamiento lógico en el SOC de Corporación Financiera del Pacífico S.A. (CFP).
Escenario de Disparo:
La alerta 01 (SSRF Autodiscover Bypass) salta en el monitor del SOC a las 09:45:03 (UTC), generada por una petición desde la dirección IP externa 103.77.192.219 hacia el servidor Exchange corporativo EXCH01.cfp-financiera.local (10.10.20.15), dirigida a /autodiscover/autodiscover.json con un parámetro @ en la query string.
                  ┌──────────────────────────────────────────────┐
                  │ ALERTA DETONADA: SSRF Autodiscover Bypass    │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ PASO 1: Enriquecimiento reputacional (VT)    │
                  │ ¿La IP de origen es catalogada maliciosa?    │
                  └──────────────────────┬───────────────────────┘
                                         ├───────────────────────── No ──> [Falso Positivo / Monitoreo]
                                         │ Sí
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ PASO 2: Confirmación de Escritura (Sysmon)   │
                  │ ¿w3wp.exe generó archivos .aspx en disco?     │
                  └──────────────────────┬───────────────────────┘
                                         ├───────────────────────── No ──> [Intento de Explotación Bloqueado]
                                         │ Sí
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ PASO 3: Validación de C2 (Sysmon ID 1)       │
                  │ ¿w3wp.exe inició consolas de comandos?       │
                  └──────────────────────┬───────────────────────┘
                                         ├───────────────────────── No ──> [Backdoor detectado / Sin ejecución]
                                         │ Sí
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ PASO 4: Evaluación de Daño Lateral e Impacto │
                  │ ¿Hubo acceso a LSASS o Exportación de Mail?  │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │     CONFIRMACIÓN DE INCIDENTE CRÍTICO        │
                  │      (Iniciar Plan de Contención)            │
                  └──────────────────────────────────────────────┘


Paso 1: Evaluación Inicial e Investigación de Red (IIS)
Objetivo: Confirmar si la alerta inicial corresponde a tráfico inusual y determinar la legitimidad del origen.
Triage Lógico: Una IP externa como 103.77.192.219 (fuera del direccionamiento privado de CFP 10.10.0.0/16 o de la VPN corporativa) no tiene justificación para enviar tráfico hacia /autodiscover/ con sintaxis @dominio-externo. Ningún cliente de Outlook o OWA legítimo utiliza esta estructura.
Búsqueda adicional en Splunk (Pivoting de Red):
index=proxylogon clientip="103.77.192.219" sourcetype="iis"
| stats count, values(cs_uri_stem) as recursos_visitados, values(sc_status) as codigos_respuesta by clientip

Resultados: El analista confirma que la IP sospechosa interactuó exclusivamente con recursos de Autodiscover y ECP, devolviendo códigos de respuesta rápidos (time-taken menor a 10ms), lo que indica un escaneo automatizado.
Enriquecimiento de Amenazas (VirusTotal): Se realiza una consulta manual de reputación para la IP 103.77.192.219 en VirusTotal. Se confirma que pertenece a un nodo malicioso reportado por múltiples firmas de seguridad y asociado históricamente a campañas dirigidas por el grupo APT Hafnium (asociado a la alerta de CISA AA21-062A).
Paso 2: Verificación de Persistencia (Escritura de Webshell en Endpoint)
Objetivo: Confirmar si el bypass de autenticación HTTP permitió al atacante escribir archivos maliciosos en los directorios del servidor web.
Búsqueda adicional en Splunk (Pivoting Endpoint):
El analista correlaciona la IP perimetral con la actividad interna del servidor EXCH01 utilizando los logs de Sysmon, buscando específicamente el Event ID 11 (Creación de Archivos):
index=proxylogon sourcetype="sysmon_otrf_real" EventCode=11 
| search file_name="*.aspx" 
| table _time, host, process_name, file_name, file_path

Resultados: Se detecta que el proceso del servidor web de IIS (w3wp.exe) escribió el archivo help.aspx en la ruta pública C:\inetpub\wwwroot\aspnet_client\system_web\. Esta acción confirma la existencia de una webshell (puerta trasera).
Paso 3: Verificación de Ejecución de Comandos (Comando y Control - C2)
Objetivo: Validar si el atacante ha logrado establecer una sesión interactiva y está ejecutando comandos dentro de la red corporativa de CFP.
Búsqueda adicional en Splunk (Pivoting de Procesos):
El analista busca Eventos de Sysmon con Event ID 1 (Creación de Procesos) para identificar subprocesos anómalos cuyo proceso padre sea el servidor web (w3wp.exe):
index=proxylogon sourcetype="sysmon_otrf_real" EventCode=1 
| search parent_process_name="*w3wp.exe" AND (process_name="*cmd.exe" OR process_name="*powershell.exe")
| table _time, host, user, parent_process_name, process_name, command_line

Resultados: Se confirma la ejecución de comandos sospechosos de reconocimiento como whoami, net user y descargas de scripts externos a través del webshell. Se confirma la intrusión activa de nivel C2.
Paso 4: Evaluación de Daño Lateral e Impacto Final
Objetivo: Medir el alcance de la intrusión para identificar si hubo robo de credenciales corporativas o fuga de información confidencial financiera.
Búsqueda de exportaciones de correo (Exfiltración):
index=proxylogon sourcetype="windows_events_proxylogon" EventCode=1 
| search command_line="*New-MailboxExportRequest*"


Búsqueda de acceso a memoria (Robo de Identidad):
El analista investiga accesos de procesos no autorizados a la memoria del proceso lsass.exe (Sysmon Event ID 10) para comprobar si se utilizaron herramientas como Mimikatz para extraer credenciales administrativas.
Categorización y Prioridad Final:
Falso Positivo: Descartado completamente.
Verdadero Positivo (TP): Confirmado con un 100% de nivel de confianza.
Severidad: Crítica. Servidor de correo de producción comprometido con acceso a nivel de . Se procede a escalar inmediatamente al Equipo de Respuesta a Incidentes (L2) para iniciar la contención.
5. PLAN DE RESPUESTA AL INCIDENTE (NIST SP 800-61 / SANS PICERL)
Con el fin de mitigar los riesgos operativos, reputacionales y financieros de Corporación Financiera del Pacífico S.A. (CFP), se implementa el siguiente plan de respuesta alineado a los estándares internacionales NIST y SANS.
    [PREPARACIÓN] ──> [DETECCIÓN Y ANÁLISIS] ──> [CONTENCIÓN] ──> [ERRADICACIÓN] ──> [RECUPERACIÓN] ──> [POST-INCIDENTE]


1. Preparación
Inventario de Activos: El servidor EXCH01 está clasificado como activo crítico de Nivel 1 debido a que gestiona comunicaciones de alta confidencialidad (datos transaccionales, directivas y correos corporativos).
Monitoreo Activo: Splunk SIEM parametrizado con las 7 alertas críticas y conectado al canal de comunicaciones de emergencia del SOC.
Roles y Contactos: Directorio de contactos de emergencia actualizado, incluyendo el Administrador de Redes (bloqueos de firewall), Administrador de Exchange (TI), Asesoría Legal (fuga de datos) y Oficial de Cumplimiento Normativo.
2. Detección y Análisis
Ejecución del protocolo de triaje detallado en la Sección 4.
Determinación del alcance: Un (1) servidor de producción Exchange afectado, posible compromiso de credenciales de dominio y exfiltración de buzones de correo.
3. Contención
Contención de Corto Plazo:
Bloquear inmediatamente la dirección IP atacante (103.77.192.219) en el Firewall perimetral de la corporación.
Remover o deshabilitar temporalmente los accesos públicos orientados a internet de la consola de administración Exchange (/ecp/) y Outlook Web App (/owa/).
Eliminar físicamente el archivo webshell identificado (help.aspx) de las carpetas de IIS para interrumpir el canal de C2.
Contención de Largo Plazo:
Aislar de forma lógica el servidor EXCH01 de la red corporativa interna (VLAN de usuarios y servidores de bases de datos) mediante microsegmentación, impidiendo cualquier intento de movimiento lateral.
Auditar las conexiones de red salientes desde el servidor Exchange para descartar otros canales de comunicación C2 activos.
4. Erradicación
Realizar un escaneo completo de persistencia en el servidor EXCH01 (búsqueda de nuevas tareas programadas, creación de cuentas de usuario locales o en Active Directory, y modificaciones en el registro de Windows).
Aplicar el Parche de Seguridad Acumulativo de Microsoft correspondiente a las vulnerabilidades de ProxyLogon (o ejecutar de manera interina la herramienta Exchange On-Premises Mitigation Tool - EOMT).
Forzar la rotación inmediata de las credenciales de todas las cuentas de servicio asociadas al ecosistema de Exchange.
Obligar a realizar un cambio preventivo de contraseña a todos los usuarios cuyos buzones de correo fueron objeto de solicitudes de exportación sospechosas.
5. Recuperación
Restaurar el servidor de correo a partir de una copia de seguridad limpia y verificada (anterior a la fecha estimada de la primera intrusión: 2021-03-02), o reconstruir el servidor Exchange desde cero aplicando parches antes de su exposición a la red.
Realizar pruebas piloto de validación de envío, recepción y autenticación de correos con un grupo reducido de usuarios.
Establecer una ventana de monitoreo intensivo de 30 días sobre el servidor, vigilando cualquier comportamiento anómalo en los logs de Sysmon y del servidor web IIS.
6. Comunicación y Notificación Regulatoria (Sector Financiero - Perú)
Dada la naturaleza regulada de Corporación Financiera del Pacífico S.A. (CFP), el proceso de respuesta incluye los siguientes canales mandatorios:
Superintendencia de Banca, Seguros y AFP (SBS): De acuerdo con la normativa vigente sobre gestión de riesgos operativos y de seguridad de la información, se realiza la notificación formal del incidente dentro del plazo regulatorio establecido, detallando el activo comprometido y las medidas de contención adoptadas.
Autoridad Nacional de Protección de Datos Personales (APDP): Si el análisis forense confirma que la exfiltración de buzones incluyó bases de datos con datos personales de clientes, se inicia el procedimiento de notificación conforme a la Ley N.° 29733 (Ley de Protección de Datos Personales en el Perú).
Clientes Afectados: En caso de confirmarse la fuga de información sensible, se emite una comunicación directa y transparente a los clientes afectados, detallando las medidas de mitigación tomadas y las recomendaciones preventivas aplicables.
Comunicación Interna: Mantener informados a la Gerencia General, al Directorio y al Oficial de Cumplimiento sobre la resolución del incidente para controlar el riesgo reputacional del negocio.
7. Lecciones Aprendidas (Informe Post-Incidente)
Resumen del Incidente: Explotación exitosa de vulnerabilidades ProxyLogon en el servidor crítico EXCH01 de CFP. El SIEM detectó el ataque en menos de un minuto a partir del inicio de la fase SSRF, logrando una contención efectiva y limitando el daño.
Causa Raíz: Existencia de vulnerabilidades críticas expuestas a Internet debido a demoras en el ciclo estándar de aplicación de parches en activos críticos.
Acciones Correctivas y Recomendaciones:
Reducir el SLA máximo para la aplicación de parches de seguridad críticos en servidores perimetrales expuestos a un plazo no mayor a 24-48 horas.
Evaluar y planificar la migración de la infraestructura de correo local hacia soluciones en la nube (Exchange Online) para delegar la gestión del ciclo de parches de infraestructura crítica.
Implementar una solución de detección y respuesta de endpoints (EDR) en todos los servidores críticos para complementar la visibilidad a nivel de memoria e hilos de ejecución.
Crear reglas adicionales en el SIEM que correlacionen de manera continua la versión de software de los activos contra bases de datos de vulnerabilidades conocidas (CVE).
eof


Resumen del documento generado y sugerencias:
He integrado detalladamente toda la información en el archivo maestro plan_triaje_respuesta_proxylogon.md. Este documento combina:
La estructura formal académica que el profesor evaluará (Cyber Kill Chain, logs multiorigen, alertas).
El escenario financiero real (Corporación Financiera del Pacífico S.A. - CFP), con IPs, nombres de servidores y contextos específicos.
El Plan de Triaje paso a paso detallando el uso de búsquedas adicionales (pivoting), VirusTotal y dashboards de Splunk.
El Plan de Respuesta formal alineado a NIST/SANS y a la legislación financiera aplicable (SBS de Perú y la Ley de Protección de Datos N.° 29733).
¿Qué hacer con este archivo?
Puedes descargarlo y usar herramientas sencillas en línea o el propio VS Code para exportarlo a formato Microsoft Word (.docx) o PDF. Esto les dará una presentación y un entregable listos para obtener la calificación máxima.
¿Deseas que prepare ahora un guion de 15 minutos paso a paso para que tú y tu equipo practiquen la sustentación del sábado y se dividan el tiempo a la perfección?
