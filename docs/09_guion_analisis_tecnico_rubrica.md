# Guión Literal — "Análisis Técnico y Lógico del Ataque" (5 pts) + apertura de SIEM (15 pts)

Organizado con los **mismos títulos exactos** que usa la rúbrica del curso, en el mismo orden, para
que quede indiscutible que cubriste cada punto. Cada sección tiene texto casi literal para leer.

---

## 1. Ciber Kill Chain

**QUÉ DECIR de apertura:**
> *"Vamos a desglosar el ataque ProxyLogon en las 7 fases del Cyber Kill Chain de Lockheed Martin:
> Reconocimiento, Weaponización, Entrega, Explotación, Instalación, Comando y Control, y Acciones
> sobre los Objetivos."*

### Fase 1 — Reconocimiento
> *"El atacante escanea masivamente internet buscando servidores Microsoft Exchange expuestos y
> vulnerables, mediante fingerprinting de la versión a través de endpoints públicos como
> `/owa/auth/logon.aspx` y `/autodiscover/`. En nuestra simulación, esto se ve como 3 direcciones IP
> distintas — 198.51.100.23, .45 y .91 — haciendo peticiones de prueba a
> `/autodiscover/autodiscover.xml`, todas rechazadas con código 403, a las 09:12 del día del
> incidente."*

### Fase 2 — Weaponización (Preparación)
> *"El atacante construye el payload: una URI de `/autodiscover/autodiscover.json` con un parámetro
> `@dominio-externo` diseñado para explotar el bug de parsing de Exchange, junto con una cookie
> `X-AnonResource-Backend` falsificada. También prepara el webshell — un archivo `.aspx` de pocas
> líneas que ejecuta cualquier comando recibido por POST."*

### Fase 3 — Entrega
> *"A diferencia de un ataque de phishing, aquí no hay correo ni archivo adjunto — la entrega es
> directa: una petición HTTP(S) normal al puerto 443 del servidor Exchange, que está expuesto
> públicamente a internet."*

### Fase 4 — Explotación (CVE-2021-26855)
> *"Esta es la vulnerabilidad que le da nombre a todo el ataque: ProxyLogon. Es un SSRF —
> Server-Side Request Forgery — pre-autenticación. La petición maliciosa hace que el frontend de
> Exchange reenvíe la solicitud a su propio backend interno, autenticándose a sí mismo como si fuera
> un proceso de confianza. El atacante obtiene así una sesión válida sin necesitar usuario ni
> contraseña, y puede leer datos de cualquier buzón de correo. El nombre 'ProxyLogon' viene
> exactamente de esto: el atacante logra un proxy hacia un logon válido."*

### Fase 5 — Instalación (CVE-2021-27065)
> *"Con el contexto autenticado obtenido en la fase anterior, el atacante abusa de una función
> administrativa de Exchange llamada `Set-OabVirtualDirectory`, accesible vía el panel ECP, para
> escribir un archivo arbitrario en el disco del servidor. Así deja caído el webshell `.aspx` en una
> carpeta accesible públicamente por web — en nuestro caso,
> `\FrontEnd\HttpProxy\owa\auth\help.aspx`, un nombre de archivo real documentado en la campaña, no
> inventado por nosotros."*

### Fase 6 — Comando y Control
> *"El atacante interactúa con el webshell mediante peticiones HTTP POST normales — indistinguibles
> de tráfico web a simple vista — enviando comandos del sistema operativo. El webshell los ejecuta
> con los privilegios del proceso `w3wp.exe`, generando procesos hijo como `cmd.exe` o
> `powershell.exe`. En nuestra simulación esto se ve como 4 comandos: `whoami`, `ipconfig /all`,
> `net user`, y un comando de PowerShell codificado en Base64."*

### Fase 7 — Acciones sobre los Objetivos
> *"Con ejecución de comandos lograda, el atacante: exporta el buzón completo de un empleado a un
> archivo `.pst` mediante el cmdlet legítimo `New-MailboxExportRequest`, accede a la memoria del
> proceso `lsass.exe` con la herramienta `procdump` para volcar credenciales, y finalmente descarga
> el archivo `.pst` exfiltrado directamente vía HTTP a través del mismo webshell."*

---

## 2. Operación Detallada

Esta sección pide 3 cosas explícitas — cúbrelas en este orden:

### a) Vulnerabilidades explotadas
> *"La cadena completa involucra 4 CVEs: CVE-2021-26855 (el SSRF ya explicado), CVE-2021-26857 (una
> deserialización insegura en el servicio de Mensajería Unificada, que permite ejecución de código
> como SYSTEM), y CVE-2021-26858 junto con CVE-2021-27065 (escritura arbitraria de archivos
> post-autenticación, el mecanismo de instalación del webshell)."*

### b) Herramientas y técnicas utilizadas
> *"Según los reportes públicos de Microsoft y Volexity, los atacantes reales usaron: scripts de
> escaneo masivo para el reconocimiento, webshells ligeros tipo China Chopper, el framework ofensivo
> de PowerShell Nishang, y la herramienta legítima de Sysinternals `procdump` — abusada para volcar
> credenciales, una técnica llamada 'living off the land': usar herramientas propias del sistema
> operativo para actividad maliciosa, dificultando la detección basada solo en firmas de malware."*

### c) Flujo de la actividad maliciosa dentro de la infraestructura
> *"El flujo completo es: internet → puerto 443 del servidor Exchange, sin autenticación → SSRF
> interno hacia el backend → sesión válida robada → escritura de archivo (webshell) → ejecución
> remota de comandos → post-explotación, con robo de credenciales y exportación de datos →
> exfiltración vía el mismo canal HTTP inicial. Es importante notar que todo el ataque ocurre a
> través de un único punto de entrada — el frontend de Exchange — sin necesitar movimiento lateral
> hacia otros servidores, lo cual también facilita la contención una vez detectado."*

---

## 3. Evidencia Digital y Artefactos

**QUÉ DECIR de apertura:**
> *"Cada fase del ataque deja artefactos digitales específicos y verificables en los sistemas
> afectados:"*

| Categoría (tal como la pide la rúbrica) | Artefacto concreto de ProxyLogon |
|---|---|
| **Registros de eventos** | Petición HTTP con `@dominio-externo` en logs de IIS; EventCode 4688 (creación de proceso) en Windows Security Log mostrando `w3wp.exe` como padre de `cmd.exe`/`powershell.exe`; EventCode 4104 (PowerShell Script Block Log) con el cmdlet `New-MailboxExportRequest` |
| **Archivos modificados** | El archivo `.aspx` nuevo (`help.aspx`) creado en una carpeta de autenticación de OWA que no debería tener archivos nuevos fuera de actualizaciones oficiales — detectable vía EventCode 4663 (acceso/escritura de objeto) |
| **Procesos sospechosos** | `procdump.exe` corriendo desde `C:\Windows\Temp\` (ubicación atípica para una herramienta administrativa) accediendo a la memoria de `lsass.exe` — EventCode 10, acceso a proceso |
| **Tráfico de red anómalo** | Peticiones con `time-taken` extremadamente bajo (8ms) indicando automatización; una descarga HTTP de tamaño y duración inusual (5200ms) correspondiente a la exfiltración del `.pst` |

**Frase de cierre de esta sección:**
> *"Estos son exactamente los artefactos que diseñamos nuestro dataset para representar, y que
> nuestras reglas de detección en Splunk buscan — no inventamos el vínculo, está anclado a lo que
> reportaron las fuentes primarias del ataque real."*

---

## 4. Detección y Respuesta al Incidente

Esta sección de la rúbrica pide 2 cosas: **equipos que producen la evidencia** y **plan de
respuesta**.

### a) Equipos que producirían la evidencia digital
> *"Cuatro sistemas distintos generan la evidencia de este ataque: el **servidor Exchange/IIS**
> genera los logs W3C de todas las peticiones HTTP entrantes — nuestra primera fuente. El **sistema
> operativo Windows** del servidor genera el Security Event Log y el PowerShell Operational Log —
> nuestra segunda fuente. Una solución **EDR/antivirus**, de estar desplegada, detectaría el
> webshell por heurística y el volcado de LSASS por comportamiento — no la simulamos por no contar
> con esa herramienta, pero la documentamos como brecha de visibilidad relevante. Y finalmente, el
> **SIEM Splunk** consolida y correlaciona las dos fuentes que sí tenemos, generando las 7 alertas
> que va a mostrar [nombre del compañero]."*

### b) Plan de respuesta al ataque
Sigue el marco **NIST SP 800-61 / SANS PICERL**, tal como está en `docs/02_plan_triage_respuesta.md`
Parte B. Guión resumido:

> *"Nuestro plan de respuesta sigue el marco NIST SP 800-61, con 6 fases:"*

1. **Preparación**: *"Exchange está clasificado como activo crítico Nivel 1 en CFP por contener
   correo con datos financieros y personales. Splunk tiene las reglas activas notificando al SOC, y
   existe un directorio de contactos de emergencia: Administrador de Redes, Administrador de
   Exchange, Asesoría Legal, y Oficial de Cumplimiento Normativo."*
2. **Detección y Análisis**: *"Cubierto por el proceso de triage — un servidor de producción
   afectado, con posible compromiso de credenciales de dominio y exfiltración de buzones."*
3. **Contención**: *"Corto plazo: bloquear la IP atacante en el firewall perimetral, deshabilitar
   temporalmente el acceso público a `/ecp/` y `/owa/`, y eliminar el archivo webshell. Largo plazo:
   aislar el servidor de la red interna mediante microsegmentación."*
4. **Erradicación**: *"Escaneo completo de persistencia — tareas programadas nuevas, cuentas de
   usuario nuevas, cambios de registro. Aplicar el parche acumulativo de Exchange correspondiente, o
   la herramienta de mitigación de emergencia de Microsoft si el parcheo inmediato no es viable.
   Rotación de credenciales de todas las cuentas de servicio."*
5. **Recuperación**: *"Restaurar desde una imagen limpia si hay sospecha de persistencia adicional,
   validar con usuarios piloto, y establecer una ventana de monitoreo reforzado de 30 días."*
6. **Comunicación y notificación regulatoria** (específico de nuestra CFP financiera): *"Por ser una
   entidad regulada, notificamos a la Superintendencia de Banca, Seguros y AFP conforme a la
   normativa de riesgo de ciberseguridad del sistema financiero peruano; a la Autoridad Nacional de
   Protección de Datos Personales si se confirma exposición de datos personales, conforme a la Ley
   29733; y comunicamos directamente a los clientes afectados si corresponde."*

---

## 5. Apertura de "Mecanismos de Detección" (transición hacia los 15 pts de SIEM)

Esta es la frase puente que cierra tu parte de análisis técnico y abre la parte de detección SIEM
(sea que la presentes tú o tu compañero):

> *"Con el ataque y sus artefactos ya caracterizados, presentamos nuestra solución SIEM: Splunk,
> configurada con un índice `proxylogon` que ingesta las dos fuentes de log mencionadas — IIS y
> Windows Event Log — y 7 alertas que detectan cada fase de este Kill Chain basadas exactamente en
> los artefactos que acabamos de describir. Vamos a mostrarlas en vivo."*

De aquí en adelante sigue `docs/07_guion_maestro_paso_a_paso.md` (Parte 4) para las 7 alertas.

---

## Checklist de auto-verificación — ¿cubriste los 4 puntos de la rúbrica?

- [ ] **Ciber Kill Chain**: las 7 fases nombradas explícitamente, en orden, con al menos una frase
      técnica por fase.
- [ ] **Operación Detallada**: vulnerabilidades (los 4 CVEs), herramientas/técnicas (webshell,
      Nishang, procdump), y el flujo completo dentro de la infraestructura.
- [ ] **Evidencia Digital y Artefactos**: las 4 categorías que pide la rúbrica textualmente
      (registros de eventos, archivos modificados, procesos sospechosos, tráfico de red anómalo),
      cada una con un ejemplo concreto de nuestro caso.
- [ ] **Detección y respuesta**: equipos que producen evidencia (4 sistemas nombrados) + plan de
      respuesta (6 fases NIST, con la fase de notificación regulatoria específica de CFP).
- [ ] Frase de transición clara hacia la parte de SIEM.
