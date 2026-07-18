# Guión Extendido — "Análisis Técnico y Lógico del Ataque" (5 pts) + apertura de SIEM (15 pts)

Versión sin límite de tiempo — máxima profundidad posible en cada punto de la rúbrica, para que
tengas material de sobra tanto para la exposición como para la ronda de preguntas. Organizado con
los mismos títulos exactos de la rúbrica, en el mismo orden.

---

## 0. Contexto general para abrir (antes de entrar al Kill Chain)

> *"ProxyLogon es el nombre asignado a una cadena de 4 vulnerabilidades de día cero descubiertas en
> Microsoft Exchange Server (versiones 2013, 2016 y 2019), explotadas activamente desde enero de
> 2021 — es decir, semanas antes de que existiera un parche — y divulgadas públicamente por
> Microsoft el 2 de marzo de 2021, en coordinación con la publicación de las actualizaciones de
> seguridad. La explotación masiva subsecuente fue atribuida al grupo HAFNIUM, un actor de amenazas
> vinculado a China y evaluado como patrocinado por el Estado. Se estima que, en las semanas
> posteriores a la divulgación, más de 250,000 servidores Exchange en todo el mundo llegaron a estar
> comprometidos, en lo que se considera uno de los incidentes de ciberseguridad más grandes de 2021.
> La investigación original fue realizada por Volexity, bajo el nombre 'Operation Exchange
> Marauder', y posteriormente ampliada por Microsoft Threat Intelligence Center (MSTIC) y por CISA,
> que emitió el advisory conjunto AA21-062A."*

**Por qué elegimos este ataque**: es real, tiene fuentes primarias verificables (no un caso
hipotético sin sustento), y el sector financiero está confirmado como uno de los efectivamente
afectados, según el reporte de ESET sobre los 10 grupos APT distintos que explotaron esta misma
cadena de vulnerabilidades tras su divulgación pública.

---

## 1. Ciber Kill Chain

**QUÉ DECIR de apertura:**
> *"Vamos a desglosar el ataque en las 7 fases del Cyber Kill Chain de Lockheed Martin —el marco de
> referencia estándar de la industria para modelar la progresión de un ciberataque—: Reconocimiento,
> Weaponización, Entrega, Explotación, Instalación, Comando y Control, y Acciones sobre los
> Objetivos."*

### Fase 1 — Reconocimiento

> *"El atacante escanea masivamente internet buscando servidores Microsoft Exchange expuestos.
> Existen múltiples técnicas de fingerprinting documentadas: consultar el banner HTTP del servidor
> IIS, revisar la respuesta del endpoint `/owa/auth/logon.aspx` (que expone la versión de Exchange
> en el código fuente de la página de login), o simplemente intentar acceder a
> `/autodiscover/autodiscover.xml` y observar el patrón de respuesta. Herramientas de escaneo masivo
> como Shodan o motores de reconocimiento propios permiten a un atacante identificar decenas de
> miles de servidores potencialmente vulnerables en cuestión de horas, sin necesidad de interacción
> humana en el objetivo — es decir, no hay phishing, no hay ingeniería social, es un reconocimiento
> puramente técnico contra infraestructura expuesta."*
>
> *"En nuestra simulación, esto se representa como 3 direcciones IP distintas — 198.51.100.23, .45
> y .91, del rango reservado para documentación (RFC 5737), seguro para usar en una demo — haciendo
> peticiones de prueba a `/autodiscover/autodiscover.xml` en un intervalo de pocos segundos entre
> sí (09:12:00, 09:12:04, 09:12:08), todas recibiendo código de respuesta 403. Ese patrón —
> múltiples IPs distintas, mismo endpoint, ventana de tiempo muy corta— es justamente la firma de un
> escaneo automatizado y no de tráfico de usuarios legítimos."*
>
> **Técnica MITRE ATT&CK**: T1595 (Active Scanning) / T1590 (Gather Victim Network Information).

### Fase 2 — Weaponización (Preparación)

> *"El atacante construye dos artefactos ofensivos distintos, uno para cada mitad de la cadena de
> explotación. El primero es el payload SSRF: una URI de
> `/autodiscover/autodiscover.json` con el parámetro `@dominio-externo` diseñado específicamente
> para abusar de un error de parsing en el componente Client Access Service de Exchange — el
> atacante descubrió (o adquirió mediante el mercado de exploits) que anteponer `@` seguido de un
> dominio arbitrario después del nombre del endpoint hace que el parser interno de rutas de Exchange
> interprete mal dónde termina la ruta y dónde empiezan los parámetros, permitiendo inyectar
> instrucciones de enrutamiento hacia el backend interno. El segundo artefacto es el webshell: un
> archivo `.aspx` de muy pocas líneas de código (típicamente variantes de 'China Chopper', un
> webshell histórico y extremadamente compacto, de apenas una línea de código ofuscado en algunos
> casos) que, al recibir una petición HTTP POST con un parámetro específico, ejecuta ese contenido
> como código del lado del servidor."*

### Fase 3 — Entrega

> *"A diferencia de un ataque de phishing o de ingeniería social, aquí no hay correo electrónico, no
> hay archivo adjunto, no hay ningún paso que dependa de que un empleado haga clic en algo. La
> entrega es directa: una petición HTTP(S) completamente normal, dirigida al puerto 443 del servidor
> Exchange, que por definición está expuesto públicamente a internet porque así es como funciona el
> correo web corporativo (OWA) y el servicio de Autodiscover para clientes externos como Outlook
> móvil. Esta es una característica importante del ataque: el vector de entrada es la superficie de
> ataque legítima y necesaria del servicio, no una vulnerabilidad de un componente periférico o mal
> configurado — cualquier organización que exponga Exchange a internet, por definición, expone este
> vector."*

### Fase 4 — Explotación (CVE-2021-26855)

> *"Esta es la vulnerabilidad que le da nombre a toda la cadena: ProxyLogon. Técnicamente es un SSRF
> — Server-Side Request Forgery — pre-autenticación, con severidad CVSS 9.1 sobre 10. El mecanismo
> exacto: Exchange tiene una arquitectura de dos capas — un frontend (Client Access Service) que
> recibe las conexiones externas, y un backend interno que realmente procesa las solicitudes de
> correo. El frontend normalmente valida la identidad del usuario antes de reenviar la petición al
> backend correspondiente. La vulnerabilidad permite que, mediante la URI manipulada de la fase
> anterior combinada con una cookie `Cookie: X-AnonResource-Backend=<servidor-backend>~<puerto>`
> falsificada, el atacante le indique al frontend exactamente a qué backend interno reenviar la
> petición — y el frontend lo hace sin validar adecuadamente que la petición viniera de un proceso
> interno de confianza. El resultado es que el atacante logra que el propio servidor Exchange se
> autentique ante su backend en nombre de un componente de confianza, sin que el atacante haya
> presentado ninguna credencial. Con esto, puede leer información arbitraria de cualquier buzón de
> correo en el servidor — incluyendo, críticamente, buzones de administradores, lo que permite
> reconocimiento adicional de la organización."*
>
> *"El nombre 'ProxyLogon' describe exactamente este mecanismo: el atacante logra un proxy hacia un
> logon válido, sin necesitar usuario ni contraseña reales."*
>
> **Técnica MITRE ATT&CK**: T1190 (Exploit Public-Facing Application).

### Fase 5 — Instalación (CVE-2021-27065, con CVE-2021-26858 como variante relacionada)

> *"Con el contexto autenticado obtenido en la fase anterior — es decir, ya con una sesión válida
> robada — el atacante procede a escribir un archivo arbitrario en el disco del servidor. El
> mecanismo específico documentado para CVE-2021-27065 es el abuso de una función administrativa de
> Exchange expuesta a través del panel ECP (Exchange Control Panel), relacionada con la gestión de
> las Libretas de Direcciones Fuera de Línea (Offline Address Book): el cmdlet
> `Set-OabVirtualDirectory`, normalmente reservado para administradores, permite configurar la URL
> externa del directorio de direcciones — y esa configuración termina escribiéndose en un archivo de
> configuración en el sistema de archivos. Al no validarse adecuadamente el contenido de ese valor,
> un atacante puede inyectar código arbitrario que termina persistido como un archivo ejecutable del
> lado del servidor. En nuestro dataset real de OTRF (Open Threat Research Forge), capturamos
> literalmente el payload usado en una ejecución real de este exploit: un webshell en JScript
> inyectado directamente en el parámetro `-ExternalUrl` del comando `Set-OabVirtualDirectory`."*
>
> *"El archivo resultante se deja caer en una carpeta accesible públicamente vía web — en nuestra
> simulación, `\FrontEnd\HttpProxy\owa\auth\help.aspx`. Es importante aclarar que `help.aspx` no es
> un nombre que inventamos: es uno de los 31 nombres de archivo de webshell documentados realmente
> en esta campaña, según un compendio de indicadores de compromiso publicado por el propio equipo de
> investigación de seguridad de Splunk, a partir de reportes de Volexity, Microsoft y Huntress Labs.
> Otros nombres reales documentados incluyen `web.aspx`, `errorEE.aspx`, `shell.aspx`, y varios
> nombres aleatorios de 8 caracteres."*
>
> **Técnica MITRE ATT&CK**: T1505.003 (Server Software Component: Web Shell).

### Fase 6 — Comando y Control

> *"Con el webshell instalado y accesible, el atacante interactúa con él mediante peticiones HTTP
> POST completamente normales — a simple vista, indistinguibles de tráfico web legítimo, ya que
> viajan sobre el mismo puerto 443 cifrado que usa cualquier cliente OWA. El contenido malicioso va
> en un parámetro de la petición, frecuentemente codificado en Base64 para evadir inspección
> superficial de contenido. El webshell interpreta ese parámetro y lo ejecuta a nivel de sistema
> operativo, con los privilegios del proceso que lo aloja — `w3wp.exe`, el proceso worker de IIS,
> que en un servidor Exchange corre típicamente con privilegios de sistema elevados dado que
> Exchange necesita interactuar profundamente con el sistema operativo y con Active Directory."*
>
> *"En nuestra simulación, esto se ve como 4 comandos ejecutados en secuencia a lo largo de
> aproximadamente 5 minutos: `whoami` (verificar privilegios), `ipconfig /all` (reconocimiento de
> red interna), `net user` (enumeración de cuentas locales, buscando objetivos para movimiento
> lateral), y un comando de PowerShell con el flag `-enc` que ejecuta instrucciones codificadas en
> Base64 — esta última es una técnica de evasión documentada extensamente: dificulta que un análisis
> superficial de logs identifique la intención real del comando sin decodificarlo primero. En la
> campaña real, se documentó el uso del framework ofensivo Nishang para estas etapas."*
>
> **Técnica MITRE ATT&CK**: T1071.001 (Application Layer Protocol: Web Protocols) para el canal de
> C2, y T1059.001 (PowerShell) para la ejecución específica de comandos codificados.

### Fase 7 — Acciones sobre los Objetivos

> *"Con ejecución de comandos arbitraria ya lograda, los objetivos post-explotación documentados en
> la campaña real, y que replicamos en nuestra simulación, son tres:"*
>
> *"Primero, **robo de credenciales**: el atacante ejecuta la herramienta legítima de Sysinternals
> `procdump.exe` — normalmente usada por administradores para diagnóstico de aplicaciones — contra
> el proceso `lsass.exe`, el proceso de Windows que mantiene en memoria las credenciales de los
> usuarios con sesión iniciada. El volcado de memoria resultante puede analizarse offline con
> herramientas como Mimikatz para extraer contraseñas en texto claro o hashes NTLM, habilitando
> movimiento lateral hacia otros sistemas de la organización."*
>
> *"Segundo, **exfiltración de datos vía Exchange PowerShell**: mediante el cmdlet legítimo
> `New-MailboxExportRequest`, propio de Exchange Management Shell y normalmente usado por
> administradores para migraciones o respaldos, el atacante exporta el contenido completo de buzones
> de correo específicos —en nuestro caso, el buzón del usuario `jgarcia`— hacia un archivo `.pst`
> guardado deliberadamente dentro de una carpeta accesible por web (`aspnet_client`), convirtiendo un
> archivo interno en algo descargable remotamente."*
>
> *"Tercero, **la exfiltración misma**: una simple petición HTTP GET, a través del mismo webshell o
> directamente a la ruta del archivo, descarga el `.pst` hacia la infraestructura del atacante. En
> nuestra simulación esta transferencia toma 5200 milisegundos — notablemente más lenta que
> cualquier otra petición del ataque, consistente con la transferencia de un archivo de tamaño
> considerable."*
>
> **Técnicas MITRE ATT&CK**: T1003.001 (OS Credential Dumping: LSASS Memory), T1114.001 (Email
> Collection: Local Email Collection), T1041 (Exfiltration Over C2 Channel).

---

## 2. Operación Detallada

La rúbrica pide explícitamente 3 elementos aquí — desarróllalos por separado y a fondo:

### a) Vulnerabilidades explotadas (las 4 CVEs, en detalle técnico)

| CVE | Componente afectado | Tipo de vulnerabilidad | CVSS | Rol específico en la cadena |
|---|---|---|---|---|
| CVE-2021-26855 | Client Access Service (frontend) | SSRF, pre-autenticación | 9.1 | Robo de sesión/autenticación sin credenciales |
| CVE-2021-26857 | Unified Messaging service | Deserialización insegura | 7.8 | Ejecución de código arbitrario con privilegios SYSTEM |
| CVE-2021-26858 | Exchange (post-auth) | Escritura arbitraria de archivos | 7.8 | Vía alternativa de escritura de archivos (a través del proceso de Exchange Information Store) |
| CVE-2021-27065 | ECP (post-auth) | Escritura arbitraria de archivos | 7.8 | Vía principal usada en la explotación masiva real para instalar webshells |

> *"Es importante notar que no las 4 vulnerabilidades son estrictamente necesarias para un ataque
> exitoso — la combinación mínima documentada como suficiente, y la más usada en la explotación
> masiva real, es CVE-2021-26855 (para el acceso inicial) más CVE-2021-27065 (para la instalación
> del webshell). CVE-2021-26857 representa una vía alternativa de ejecución de código que no
> necesariamente se usó en todas las campañas de explotación observadas."*

### b) Herramientas y técnicas utilizadas por los atacantes

> *"Según los reportes públicos de Microsoft, Volexity y la comunidad de threat intelligence, el
> arsenal documentado incluye:"*
> - *"Scripts de escaneo masivo personalizados para el reconocimiento a escala de internet."*
> - *"Webshells ligeros tipo 'China Chopper' — un webshell histórico, extremadamente compacto (a
>   veces una sola línea de código), que se comunica con un cliente de administración remota
>   dedicado."*
> - *"El framework ofensivo de PowerShell 'Nishang', que provee funciones para shells inversas,
>   escaneo de red interno y post-explotación."*
> - *"`procdump.exe` de Sysinternals, una herramienta 100% legítima de Microsoft, abusada para el
>   volcado de memoria de LSASS — un ejemplo textbook de la técnica 'living off the land': usar
>   binarios y herramientas ya presentes o fácilmente justificables en el sistema, en vez de malware
>   personalizado, dificultando la detección basada en firmas."*
> - *"7-Zip u otras herramientas de compresión, documentadas en variantes de la campaña para
>   comprimir grandes volúmenes de datos exfiltrados antes de la descarga."*
> - *"El propio cmdlet `New-MailboxExportRequest`, nativamente parte de Exchange — otro ejemplo de
>   abuso de funcionalidad legítima."*

### c) Flujo de la actividad maliciosa dentro de la infraestructura de la organización

> *"El flujo end-to-end completo, tal como ocurre dentro de la infraestructura de CFP: internet →
> puerto 443 del servidor Exchange expuesto (sin autenticación) → SSRF interno hacia el backend de
> Client Access Service → sesión/contexto autenticado robado → abuso de función administrativa ECP →
> escritura de archivo (webshell) en el sistema de archivos del servidor → peticiones HTTP
> subsecuentes al webshell, ejecutando comandos arbitrarios con privilegios del proceso `w3wp.exe` →
> reconocimiento local del sistema y del dominio → volcado de credenciales desde LSASS → abuso de
> Exchange Management Shell para exportar buzones → exfiltración final vía HTTP a través del mismo
> canal usado desde el inicio."*
>
> *"Un punto arquitectónico importante para destacar: **todo el ataque transcurre a través de un
> único punto de entrada** — el frontend de Exchange — sin necesitar moverse lateralmente hacia
> otros servidores de la red de CFP. Esto tiene dos implicaciones: primero, facilita la contención
> una vez detectado, porque aislar un solo servidor corta toda la cadena; segundo, explica por qué
> nuestras dos fuentes de log —IIS y Windows Event Log, ambas del mismo servidor Exchange— son
> suficientes para cubrir la detección de las 7 fases completas del ataque, sin necesitar
> instrumentar otros sistemas de la red."*

---

## 3. Evidencia Digital y Artefactos

La rúbrica pide 4 categorías textuales explícitas — cúbrelas todas, con ejemplos concretos:

### Registros de eventos
> *"En los logs de IIS: la petición con `@dominio-externo` en la URI, con código de respuesta 241
> (un código interno de Exchange no estándar) y un `time-taken` de apenas 8 milisegundos —
> demasiado rápido para interacción humana. En Windows Event Log: EventCode 4688 (creación de
> proceso) mostrando `w3wp.exe` como proceso padre de `cmd.exe` o `powershell.exe`; EventCode 4104
> (registro de bloques de script de PowerShell) capturando el contenido completo de comandos
> ejecutados, incluyendo el cmdlet `New-MailboxExportRequest`; y EventCode 10 (acceso a proceso, en
> el estilo de Sysmon) registrando el acceso de `procdump.exe` a la memoria de `lsass.exe`."*

### Archivos modificados (o creados)
> *"El artefacto más directo: el archivo `.aspx` nuevo, aparecido en una fecha fuera de cualquier
> ventana de actualización oficial de Exchange, en una carpeta de autenticación de OWA que
> normalmente no debería recibir archivos nuevos — `help.aspx`, en nuestro caso. Este evento de
> creación de archivo queda registrado como EventCode 4663 (acceso a objeto del sistema de archivos)
> con el proceso `w3wp.exe` como responsable de la escritura, un hecho en sí mismo anómalo: el
> proceso de IIS no debería estar escribiendo archivos ejecutables nuevos durante operación normal."*

### Procesos sospechosos
> *"Dos patrones de proceso claramente anómalos: primero, `w3wp.exe` (el proceso que sirve páginas
> web) generando procesos hijo tipo `cmd.exe` o `powershell.exe` — algo que jamás ocurre en
> operación normal de un servidor Exchange sin explotación activa. Segundo, `procdump.exe`
> ejecutándose desde una ubicación atípica —`C:\Windows\Temp\`, la carpeta temporal del sistema, no
> donde normalmente residiría una herramienta administrativa instalada intencionalmente— y accediendo
> a la memoria de un proceso crítico del sistema como `lsass.exe`."*

### Tráfico de red anómalo
> *"Varios patrones distintos: peticiones con sintaxis de URI que nunca aparece en tráfico legítimo
> de clientes Outlook/OWA (el patrón `@dominio-externo`); un volumen de peticiones desde IPs
> externas hacia endpoints administrativos (`/ecp/`) que normalmente solo deberían recibir tráfico
> desde la red interna de administradores; y una transferencia HTTP de tamaño y duración inusuales
> (5200 milisegundos) correspondiente a la descarga del archivo `.pst` exfiltrado — un patrón de
> transferencia de datos considerablemente más grande y lento que el tráfico web típico de esa ruta."*

**Frase de cierre de esta sección:**
> *"Diseñamos deliberadamente nuestro dataset de simulación para representar exactamente estos
> artefactos — no los inventamos libremente, están anclados 1 a 1 a lo que reportaron las fuentes
> primarias de la investigación del ataque real, y adicionalmente los validamos contra un dataset
> público real de ejecución del exploit, publicado por el equipo de investigación OTRF, que
> mostraremos más adelante en la Regla 6 de detección."*

---

## 4. Detección y Respuesta al Incidente

La rúbrica pide 2 elementos: **equipos que producen la evidencia** y **plan de respuesta**.

### a) Equipos que producirían la evidencia digital

> *"Identificamos 4 sistemas distintos con un rol específico en la generación de evidencia:"*
>
> - *"**El servidor Exchange/IIS**: genera los logs W3C Extended Log Format de absolutamente todas
>   las peticiones HTTP/HTTPS entrantes al servicio — nuestra primera fuente de log, y la que
>   primero mostraría indicios de explotación."*
> - *"**El sistema operativo Windows** del servidor: genera el Security Event Log (creación de
>   procesos, acceso a objetos) y el PowerShell Operational Log (contenido de scripts ejecutados) —
>   nuestra segunda fuente, y la que confirma que la explotación efectivamente resultó en ejecución
>   de código, no solo en un intento fallido."*
> - *"**Una solución EDR/antivirus**, de estar desplegada: detectaría el webshell por firma o
>   heurística de comportamiento, y el volcado de LSASS por su patrón de acceso a memoria —
>   documentamos esto como una brecha de visibilidad relevante en nuestro análisis, dado que no
>   contamos con esa herramienta en la simulación, pero es una recomendación explícita en nuestras
>   lecciones aprendidas."*
> - *"**El SIEM Splunk**: no genera evidencia primaria, pero consolida, normaliza y correlaciona las
>   dos fuentes que sí tenemos, generando las 7 alertas automatizadas que detectan cada fase del
>   ataque — esta es la pieza que conecta el análisis forense con la detección operacional en tiempo
>   real."*
>
> *"Adicionalmente, mencionamos en nuestro análisis (aunque fuera del alcance de esta simulación de
> 2 fuentes) que un firewall/proxy perimetral registraría la conexión entrante original y cualquier
> tráfico saliente anómalo — una tercera fuente recomendada para un entorno de producción real."*

### b) Plan de respuesta al ataque (marco NIST SP 800-61 / SANS PICERL)

> *"Diseñamos nuestro plan de respuesta siguiendo el marco NIST SP 800-61 Rev. 2, ampliamente
> adoptado y con 6 fases:"*

**1. Preparación** (lo que ya debía existir antes del incidente):
> *"El servidor Exchange está clasificado como activo crítico Nivel 1 dentro del inventario de
> riesgos de CFP, por contener correspondencia con datos financieros y personales de clientes.
> Splunk tiene las 5 reglas de correlación activas, notificando al canal de comunicaciones del SOC.
> Existe un directorio de contactos de emergencia predefinido: Administrador de Redes (para
> bloqueos de firewall), Administrador de Exchange/TI (para aislar el host), Asesoría Legal y
> Oficial de Cumplimiento (dado el rol regulado de CFP como entidad financiera), y el Área de
> Comunicaciones (para eventual notificación a clientes y al regulador)."*

**2. Detección y Análisis**:
> *"Esta fase está cubierta en detalle por nuestro proceso de triage — evaluación inicial, análisis
> lógico, enriquecimiento con VirusTotal, categorización como Falso o Verdadero Positivo,
> asignación de prioridad, y escalamiento. Al confirmarse el ataque, se documenta: alcance (1
> servidor Exchange comprometido), impacto potencial (posible exfiltración de buzones de correo vía
> `.pst`, posible compromiso de credenciales de dominio), y causa raíz preliminar (CVE-2021-26855 y
> CVE-2021-27065 sin parchear en el momento del incidente)."*

**3. Contención**:
> *"Corto plazo: bloquear inmediatamente la IP atacante (`103.77.192.219`) en el firewall
> perimetral; deshabilitar temporalmente el acceso público a `/ecp/` y `/owa/` si es operativamente
> viable, o como mínimo eliminar/renombrar el archivo webshell identificado. Largo plazo: aislar
> lógicamente el servidor Exchange de segmentos de red no esenciales mediante microsegmentación,
> impidiendo cualquier intento de movimiento lateral, y auditar las conexiones salientes del
> servidor para descartar canales de C2 adicionales no detectados."*

**4. Erradicación**:
> *"Realizar un escaneo completo de persistencia en el servidor: búsqueda de tareas programadas
> nuevas, cuentas de usuario locales o de Active Directory creadas sin autorización, y
> modificaciones sospechosas al registro de Windows. Aplicar el parche acumulativo de seguridad de
> Microsoft correspondiente a las vulnerabilidades de ProxyLogon — o, si el parcheo inmediato no es
> viable operativamente, ejecutar la herramienta de mitigación de emergencia que Microsoft publicó
> específicamente para este caso, el Exchange On-Premises Mitigation Tool (EOMT). Forzar la rotación
> inmediata de credenciales de todas las cuentas de servicio asociadas al ecosistema Exchange, y
> obligar el cambio de contraseña a los usuarios cuyos buzones fueron objeto de exportación
> sospechosa."*

**5. Recuperación**:
> *"Restaurar el servidor desde una imagen limpia y verificada si se sospecha persistencia
> adicional no descubierta en la fase de erradicación, o reconstruir el servidor desde cero
> aplicando los parches antes de reexponerlo a la red. Realizar pruebas piloto de envío, recepción y
> autenticación de correo con un grupo reducido de usuarios antes de reabrir el servicio a toda la
> organización. Establecer una ventana de monitoreo reforzado de 30 días sobre el host afectado y
> sobre el rango de IPs asociado al atacante."*

**6. Comunicación y notificación regulatoria** (elemento específico de nuestra CFP financiera,
más allá de las 6 fases estándar de NIST):
> *"Por ser CFP una entidad financiera regulada, la respuesta no termina en lo técnico. Se notifica
> a la Superintendencia de Banca, Seguros y AFP (SBS), conforme a la normativa de gestión de riesgo
> operacional y de ciberseguridad aplicable al sistema financiero peruano, detallando el activo
> comprometido y las medidas de contención adoptadas. Si el análisis forense confirma exfiltración
> de datos personales de clientes, se inicia el procedimiento de notificación a la Autoridad
> Nacional de Protección de Datos Personales, conforme a la Ley N.° 29733. Si se confirma exposición
> de información sensible, se emite comunicación directa y transparente a los clientes afectados,
> detallando qué ocurrió y qué medidas preventivas se recomiendan. Y se mantiene informados,
> durante todo el proceso, a la Gerencia General y al Directorio, dado el riesgo reputacional propio
> de una entidad financiera."*

**7. Lecciones aprendidas / Informe post-incidente** (cierre del ciclo):
> *"El informe final documenta: un resumen ejecutivo del incidente; la causa raíz identificada —
> típicamente, demoras en el ciclo de aplicación de parches críticos en activos expuestos a
> internet—; y recomendaciones concretas: reducir el SLA máximo de aplicación de parches críticos en
> servidores perimetrales a un plazo no mayor de 24-48 horas; evaluar la migración de la
> infraestructura de correo hacia una solución en la nube (Exchange Online) para delegar la gestión
> del ciclo de parches; desplegar una solución EDR en los servidores críticos para complementar la
> visibilidad que actualmente no tenemos a nivel de memoria y comportamiento de procesos; y agregar
> una regla adicional en el SIEM que correlacione continuamente la versión de software de los
> activos críticos contra bases de datos de vulnerabilidades conocidas."*

---

## 5. Apertura de "Mecanismos de Detección" (transición hacia los 15 pts de SIEM)

> *"Con el ataque, su operación técnica, sus artefactos y el plan de respuesta ya caracterizados,
> presentamos ahora nuestra solución de detección: un SIEM Splunk, configurado con un índice
> `proxylogon` que ingesta las dos fuentes de log ya mencionadas — logs de IIS y Windows Event Log
> del servidor Exchange de CFP — y 7 reglas de correlación que detectan cada fase de este Kill Chain,
> construidas exactamente sobre los artefactos digitales que acabamos de describir. Vamos a
> mostrarlas funcionando en vivo."*

De aquí en adelante, sigue `docs/07_guion_maestro_paso_a_paso.md` (Parte 4) para el detalle
completo de cada una de las 7 alertas.

---

## Preguntas de profundización — prepárate para que te pidan más detalle en cualquiera de estos puntos

- **Sobre el Kill Chain**: ¿por qué el reconocimiento no requiere interacción del usuario, a
  diferencia de un ataque de phishing? ¿Por qué se dice que ProxyLogon no necesita movimiento
  lateral para lograr su objetivo?
- **Sobre las vulnerabilidades**: ¿cuál es la diferencia técnica entre CVE-2021-26858 y
  CVE-2021-27065, si ambas son "escritura arbitraria de archivos"? (Respuesta: usan mecanismos/
  componentes distintos de Exchange para lograr el mismo resultado — 26858 vía el proceso de
  Information Store, 27065 vía ECP — es la vía documentada como más usada en la explotación real.)
- **Sobre las herramientas**: ¿por qué "living off the land" (usar procdump legítimo) es más
  peligroso de detectar que malware personalizado? (Respuesta: no dispara firmas de antivirus
  tradicionales, porque el binario en sí es legítimo y firmado por Microsoft — la detección debe
  basarse en comportamiento y contexto, no en la identidad del archivo.)
- **Sobre los artefactos**: si el atacante cambia el nombre del webshell, ¿cómo lo seguirían
  detectando? (Respuesta: nuestra Regla 3 no depende del nombre del archivo, depende del patrón de
  comportamiento — `w3wp.exe` generando una shell — que es estructuralmente imposible de evitar si
  el atacante quiere ejecutar comandos a través del webshell.)
- **Sobre el plan de respuesta**: ¿qué pasaría si el parche no se puede aplicar de inmediato por
  restricciones operativas? (Respuesta: el Exchange On-Premises Mitigation Tool de Microsoft, una
  mitigación de emergencia que no requiere downtime completo del servicio.)
