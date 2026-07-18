# Análisis Técnico y Lógico del Ataque — ProxyLogon (5 pts)

## 0. Organización objetivo (hipotética)

**Corporación Financiera del Pacífico S.A. (CFP)** — entidad financiera peruana regulada, dedicada a
banca de consumo y financiamiento empresarial (créditos personales, tarjetas de crédito, líneas de
capital de trabajo para pymes), con aproximadamente 850 empleados y presencia en 30 agencias a nivel
nacional. Organización enteramente ficticia creada para este proyecto, conforme a lo aprobado en la
propuesta del curso ("empresa del sector financiero con servidor Microsoft Exchange expuesto a
internet"); cualquier parecido con una entidad real es coincidencia.

**Por qué el sector financiero es una elección defendible y no arbitraria**: el sector financiero
está confirmado como uno de los sectores efectivamente comprometidos en la campaña de explotación de
ProxyLogon documentada por ESET, que identificó al menos 10 grupos APT distintos explotando esta
misma cadena de vulnerabilidades contra organizaciones de finanzas, gobierno, defensa, legal y manu-
factura en múltiples países ([ESET, "Exchange servers under siege from at least 10 APT groups"](https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/)).
No es una combinación forzada: es consistente con lo que realmente ocurrió en la campaña real.

**Infraestructura relevante**:
- Servidor Microsoft Exchange on-premise (`EXCH01.cfp-financiera.local`, IP interna `10.10.20.15`)
  que aloja el correo corporativo institucional, incluyendo el de la fuerza comercial (asesores de
  negocio, gerentes de agencia) y del área de riesgos.
- Desde 2019, CFP expuso el frontend de Exchange (Outlook Web App, ECP y Autodiscover, puerto 443)
  directamente a internet para que la fuerza comercial pudiera acceder a su correo desde las agencias
  y en visitas a clientes sin depender de una VPN corporativa completa — decisión operativa razonable
  en su momento, que sin embargo amplía la superficie de ataque exactamente sobre el componente que
  expone CVE-2021-26855 (el frontend de Client Access Service).
- El servidor Exchange está clasificado como **activo crítico** dentro del inventario de riesgos de
  CFP: los buzones contienen información financiera y datos personales de clientes (solicitudes de
  crédito, evaluaciones de riesgo, estados de cuenta adjuntos), sujeta a la **Ley N.° 29733 de
  Protección de Datos Personales** del Perú.
- Por ser una entidad financiera regulada, CFP tiene obligación de reportar incidentes de
  ciberseguridad relevantes a la **Superintendencia de Banca, Seguros y AFP (SBS)**, conforme a la
  normativa de gestión de riesgo operacional y ciberseguridad aplicable al sistema financiero
  peruano.

**Por qué este contexto importa para el análisis** (y no es solo ambientación): explica (a) la causa
raíz de negocio detrás de la superficie de ataque — por qué el frontend de Exchange estaba expuesto a
internet en primer lugar, (b) por qué el activo tiene clasificación crítica — datos financieros y
personales de clientes, no solo correo genérico, y (c) a quién hay que notificar además del equipo
técnico durante la respuesta al incidente — SBS, la Autoridad Nacional de Protección de Datos
Personales si hay compromiso de datos personales, y los propios clientes afectados. Estos tres puntos
se retoman en el plan de respuesta (`02_plan_triage_respuesta.md`).

## 1. Contexto del ataque

**ProxyLogon** es el nombre asignado a una cadena de 4 vulnerabilidades encontradas en Microsoft
Exchange Server (2013/2016/2019), explotadas activamente como *zero-day* desde enero de 2021 y
divulgadas por Microsoft el 2 de marzo de 2021. Fue explotado masivamente por el grupo asociado a
China conocido como **HAFNIUM**, y documentado en detalle por **Volexity** ("Operation Exchange
Marauder") y por el propio **Microsoft Threat Intelligence Center (MSTIC)**.

| CVE | Componente | Tipo | Rol en la cadena |
|---|---|---|---|
| CVE-2021-26855 | Client Access Service (frontend) | SSRF, pre-autenticación | Permite hacerse pasar por un usuario legítimo y robar datos de buzones sin credenciales |
| CVE-2021-26857 | Unified Messaging service | Deserialización insegura | Ejecución de código como SYSTEM |
| CVE-2021-26858 | Exchange (post-auth) | Escritura arbitraria de archivos | Escribir archivos en cualquier ruta del servidor |
| CVE-2021-27065 | ECP (post-auth) | Escritura arbitraria de archivos | Vía usada en la explotación masiva para dejar webshells |



El nombre "ProxyLogon" viene de que el atacante logra un **proxy hacia un logon válido**: usa el
SSRF para que el propio servidor Exchange se autentique a sí mismo en nombre de un usuario, sin
necesitar la contraseña real.

adjunto:
en ciberseguridad, ciertas alertas posteriores actúan como un "efecto dominó" que delata la existencia de la vulnerabilidad inicial.  Para el caso de ProxyLogon, las vulnerabilidades compañeras que demuestran que el CVE-2021-26855 ocurrió son el CVE-2021-27065 (o el CVE-2021-26858).  Aquí tienes la lógica técnica exacta para explicárselo al jurado y dejarlos con la boca abierta::link: La Lógica de la Cadena: ¿Por qué uno demuestra el otro?CVE-2021-26855 (El SSRF): Es una vulnerabilidad pre-autenticación (el atacante no necesita usuario ni clave para explotarla).  CVE-2021-27065 (Escritura del Archivo / Webshell): Es una vulnerabilidad post-autenticación. Esto significa que, bajo condiciones normales, solo un administrador legítimo con credenciales válidas podría escribir archivos en esos directorios de Exchange.  :bulb: El argumento forense irrefutable: Si tu SIEM detecta que un usuario no autenticado (la IP externa) logró activar el CVE-2021-27065 para escribir la webshell help.aspx, implícitamente se demuestra la presencia del CVE-2021-26855. El atacante usó el SSRF como un "puente" para saltarse la autenticación y poder ejecutar el segundo CVE.  :speaking_head: Cómo decírselo al Jurado (Guion Pro)Muestra el panel donde se ve la creación del archivo (la Webshell) y dilo así:"Profesor, un punto crucial aquí es que estamos ante un Exploit Chain corporativo. Al analizar los logs de Windows, detectamos la presencia del CVE-2021-27065, que es una vulnerabilidad de escritura arbitraria de archivos post-autenticación utilizada para dropear la webshell.  Como esta acción requiere privilegios de administrador que el atacante externo no poseía, el hallazgo de este segundo código confirma e indica de forma automática la explotación exitosa del CVE-2021-26855. El SSRF fue el vector necesario para engañar al backend de Exchange, omitir la autenticación y permitir que el CVE-2021-27065 tomara el control del servidor. Una fase no puede existir sin la otra en este tipo de incidentes


## 2. Cyber Kill Chain

### Reconocimiento
El atacante escanea masivamente Internet buscando servidores Exchange expuestos y su versión
(fingerprinting vía `/owa/auth/logon.aspx`, cabeceras de respuesta, `/ecp/`, `/autodiscover/`).
No requiere interacción del usuario ni acceso previo.

### Preparación (Weaponización)
Se construye el payload de la petición SSRF: una URI de `/autodiscover/autodiscover.json` con un
parámetro `@dominio-externo` y una cookie `X-AnonResource-Backend` que apunta a un backend interno
arbitrario de Exchange. También se prepara el webshell `.aspx` (comúnmente una variante ligera tipo
"China Chopper", de un par de líneas, que ejecuta cualquier comando recibido por POST).

### Entrega
El payload SSRF se entrega como una petición HTTP(S) normal al puerto 443 del servidor Exchange
público — no hay email de phishing ni archivo adjunto: la entrega es directamente contra el servicio
expuesto a Internet.

### Explotación — CVE-2021-26855
La petición SSRF hace que el frontend de Exchange reenvíe la solicitud a su propio backend interno
autenticándose como si fuera un proceso de confianza. El atacante obtiene así una cookie de sesión
válida sin conocer usuario ni contraseña, y puede leer datos de cualquier buzón de correo
(incluyendo el buzón del administrador, útil para reconocimiento adicional).

### Instalación — CVE-2021-27065
Con el contexto autenticado obtenido, el atacante envía un POST a un endpoint de administración de
ECP (`/ecp/`) que, por una validación insuficiente, permite escribir un archivo arbitrario en el
sistema de archivos del servidor. Así se deja caer el webshell `.aspx` en una carpeta accesible
públicamente vía web (típicamente bajo `\FrontEnd\HttpProxy\owa\auth\` o rutas similares dentro de
`\FrontEnd\HttpProxy\ecp\`).

### Comando y Control
El atacante interactúa con el webshell mediante peticiones HTTP POST normales (indistinguibles de
tráfico web a simple vista), enviando comandos del sistema operativo codificados. El webshell los
ejecuta con los privilegios del proceso `w3wp.exe` (habitualmente `SYSTEM` o una cuenta de servicio
con privilegios altos en Exchange), generando procesos hijos como `cmd.exe` o `powershell.exe`.

### Acciones sobre los objetivos
Con ejecución de comandos ya lograda, los objetivos típicos observados en el ataque real fueron:
- **Reconocimiento del entorno** (`whoami`, `ipconfig /all`, `net user`).
- **Exportación masiva de buzones** de correo a archivos `.pst` mediante el cmdlet de Exchange
  Management Shell `New-MailboxExportRequest`, guardando el resultado en una carpeta accesible vía
  web para poder descargarlo después.
- **Volcado de credenciales**: acceso al proceso `lsass.exe` (por ejemplo con `procdump`) para
  extraer hashes/credenciales y facilitar movimiento lateral.
- **Exfiltración**: descarga del archivo `.pst` (u otros datos recolectados) directamente vía HTTP
  a través del propio webshell.
- En campañas reales posteriores, además se desplegó ransomware (ej. variantes de DearCry) usando
  el mismo acceso, aunque eso queda fuera del alcance de esta simulación.

## 3. Vulnerabilidades explotadas, herramientas y flujo (resumen técnico)

- **Vulnerabilidad raíz**: falta de validación adecuada de la ruta/URI en el proceso de proxy
  interno de Exchange (CVE-2021-26855) combinada con controles de autorización insuficientes en
  funciones administrativas de ECP (CVE-2021-27065).
- **Herramientas usadas por el atacante (según reportes públicos)**: scripts de escaneo masivo,
  webshells ligeros (variantes de China Chopper), `Nishang` (framework de PowerShell ofensivo),
  `procdump` (herramienta legítima de Sysinternals, abusada para volcar LSASS), PowerShell nativo de
  Exchange Management Shell.
- **Flujo end-to-end**: Internet → puerto 443 del servidor Exchange (sin autenticación) → SSRF
  interno → sesión válida robada → escritura de archivo (webshell) → ejecución remota de comandos →
  post-explotación (credenciales, exportación de datos) → exfiltración vía el mismo canal HTTP.

## 4. Evidencia digital y artefactos esperados

| Artefacto | Dónde queda el rastro | Por qué es evidencia |
|---|---|---|
| Petición HTTP con `@dominio-externo` en la URI de `/autodiscover/` o `/ecp/` | Logs de IIS del servidor Exchange | Patrón de URI que nunca ocurre en tráfico legítimo de Autodiscover |
| Cookie/header `X-AnonResource-Backend` o `X-BEResource` en requests sin autenticación previa | Logs de IIS | Mecanismo interno de Exchange, no debería llegar desde clientes externos anónimos |
| Archivo `.aspx` nuevo en una carpeta de autenticación de OWA/ECP, con fecha de creación fuera de ventanas de mantenimiento | Sistema de archivos del servidor / Windows Security Log (EventID 4663, escritura de archivo) | Los despliegues legítimos de Exchange no crean archivos nuevos ahí fuera de actualizaciones oficiales |
| `w3wp.exe` como proceso padre de `cmd.exe` o `powershell.exe` | Windows Security Log (EventID 4688, creación de proceso) | El proceso de IIS/Exchange nunca debería generar una shell interactiva en operación normal |
| Cmdlet `New-MailboxExportRequest` ejecutado fuera de una ventana de migración planificada | PowerShell Operational Log (EventID 4103/4104) | Exportar buzones completos a `.pst` es una operación administrativa poco frecuente y sensible |
| Proceso no estándar (ej. `procdump.exe`) accediendo a `lsass.exe` con permisos de lectura de memoria | Windows Sysmon/Security Log (EventID 10) | Acceso a LSASS es la técnica clásica de volcado de credenciales (T1003.001 en MITRE ATT&CK) |
| Tráfico de red anómalo: descargas grandes o repetidas hacia la misma IP externa poco después de la creación del webshell | Logs de IIS (tamaño de respuesta, `time-taken`) / NetFlow si estuviera disponible | Indicador de exfiltración de datos |

## 5. Equipos que producirían la evidencia digital

- **Servidor Exchange (IIS)**: genera los logs W3C de todas las peticiones HTTP/HTTPS entrantes —
  primera fuente de evidencia de explotación y C2.
- **Sistema operativo Windows del servidor Exchange**: genera el Security Event Log (creación de
  procesos, acceso a objetos) y el PowerShell Operational Log — evidencia de ejecución de comandos y
  post-explotación.
- **Solución EDR/antivirus** (si estuviera desplegada): detectaría el webshell por firma/heurística
  y el volcado de LSASS por comportamiento — no simulado en este proyecto por no contar con esa
  herramienta, pero se documenta como brecha de visibilidad relevante.
- **Firewall/Proxy perimetral**: registraría la conexión entrante original y cualquier conexión
  saliente inusual — mencionado como fuente adicional recomendada, fuera del alcance de las 2
  fuentes usadas en esta simulación.
- **SIEM (Splunk)**: consolida y correlaciona las dos fuentes anteriores (IIS + Windows Event Logs)
  para generar las alertas descritas en [`03_guia_splunk.md`](03_guia_splunk.md).

## 6. Mapeo a MITRE ATT&CK (referencia rápida para la ronda de preguntas)

| Fase | Técnica MITRE ATT&CK |
|---|---|
| Explotación (SSRF) | T1190 — Exploit Public-Facing Application |
| Instalación (webshell) | T1505.003 — Server Software Component: Web Shell |
| C2 vía webshell | T1071.001 — Application Layer Protocol: Web Protocols |
| Exportación de buzones | T1114.001 — Email Collection: Local Email Collection |
| Volcado de LSASS | T1003.001 — OS Credential Dumping: LSASS Memory |
| Exfiltración vía webshell | T1041 — Exfiltration Over C2 Channel |

## 7. Plan de respuesta al incidente (resumen — detalle completo en `02_plan_triage_respuesta.md`)

1. **Contención inmediata**: aislar el servidor Exchange de la red (o al menos bloquear la IP
   atacante en el firewall perimetral) y deshabilitar el webshell identificado.
2. **Erradicación**: eliminar el/los archivos `.aspx` maliciosos, aplicar los parches de seguridad
   de marzo de 2021 (o el script de mitigación de emergencia de Microsoft si no se puede parchear de
   inmediato), rotar credenciales de cuentas de servicio de Exchange.
3. **Recuperación**: validar integridad del servidor (comparar con backup limpio o reinstalar si hay
   evidencia de persistencia adicional), restaurar operación normal, monitoreo reforzado 30 días.
4. **Lecciones aprendidas**: documentar cronología completa, causa raíz (parche no aplicado a
   tiempo), y actualizar el plan de gestión de vulnerabilidades críticas.
