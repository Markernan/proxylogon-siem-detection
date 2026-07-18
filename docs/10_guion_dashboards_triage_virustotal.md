# Guión — Dashboard Overview, Dashboard Detalle por Fase, y Plan de Triage + VirusTotal

Todos los timestamps y datos de este documento están verificados contra los datos reales indexados
en Splunk (no son aproximaciones). Fecha del incidente simulado: **2026-07-16**.

---

## PARTE 1 — Dashboard "ProxyLogon - Overview"

**CLIC**: menú superior → Dashboards → "ProxyLogon - Overview".

### Panel 1: Volumen de eventos por fuente (picos de tráfico)
> *"Este es el gráfico de picos de tráfico que exige la rúbrica como una de las propiedades nativas
> del SIEM que debemos demostrar. Es un `timechart` de Splunk, que agrupa los eventos en bloques de
> 30 minutos y cuenta cuántos hay de cada fuente — IIS en un color, Windows Event Log en otro. Nos
> permite ver de un vistazo si hubo un pico anómalo de actividad, por ejemplo durante la ventana del
> ataque entre las 09:12 y las 09:54."*

### Paneles de contadores (Regla 1, Regla 3, Regla 4, Regla 5)
> *"Cuatro contadores en vivo, cada uno resultado de una búsqueda SPL corriendo contra los datos en
> este momento — no son números fijos escritos a mano."*

### Panel "Falsos Positivos Regla 1"
> *"Este panel responde directamente a la instrucción que el profesor nos dio al aprobar la
> propuesta: no olvidar confirmar que no es un falso positivo. El valor es 0, en verde."*

### Panel "Top IPs origen"
> *"Permite identificar de un vistazo cuál IP es la anómala entre el tráfico normal de los
> empleados de CFP — la tabla muestra las IPs internas legítimas (rango 192.168.1.x) junto con la
> IP del atacante, para contraste."*

---

## PARTE 2 — Dashboard "ProxyLogon - Detalle por Fase"

**CLIC**: menú superior → Dashboards → "ProxyLogon - Detalle por Fase".

> *"Este dashboard recorre las 9 etapas completas del ataque, en orden cronológico, cada una con su
> evidencia específica."*

1. **Fase 1 - Reconocimiento** (09:12:00 - 09:12:08): *"Tres IPs del rango 198.51.100.x escaneando
   `/autodiscover/autodiscover.xml`, todas rechazadas con 403 — el sondeo previo al ataque real."*
2. **Fase 2 - Explotación** (09:45:00 - 09:46:05): *"El bypass SSRF, 6 peticiones con el patrón
   `@dominio-externo`, todas desde la IP 103.77.192.219, confirmada como IOC real vía el comando
   `lookup`."*
3. **Fase 3 - Instalación** (09:46:05 - 09:46:20): *"El POST que escribe el webshell, y el GET que
   lo confirma accesible 15 segundos después."*
4. **Fase 4 - Comando y Control** (09:46:46 - 09:51:01): *"Los 4 comandos ejecutados vía el
   webshell, con `w3wp.exe` como proceso padre."*
5. **Fase 5a - Exportación de buzón** (09:52:00): *"El cmdlet `New-MailboxExportRequest` exportando
   el buzón de jgarcia."*
6. **Fase 5b - Acceso a LSASS** (09:53:30): *"`procdump.exe` volcando la memoria de `lsass.exe`."*
7. **Fase 5c - Exfiltración** (09:54:15): *"La descarga final del `.pst`, con `time_taken` de 5200
   milisegundos."*
8. **Línea de tiempo completa**: *"Las 9 etapas juntas en una sola tabla — 42 minutos de principio a
   fin, desde el primer escaneo hasta la exfiltración confirmada."*
9. **Validación cruzada con dataset real OTRF**: *"El mismo patrón `w3wp.exe → cmd.exe` encontrado
   en una ejecución real y pública del exploit, capturada por el equipo de investigación OTRF en
   2021."*

---

## PARTE 3 — Plan de Triage y Confirmación (versión corregida y lista para leer)

Estructura: 5 momentos de inyección/hallazgo + fase de contención, con el **Analista SOC Nivel 1**
como rol narrador. Todos los timestamps son los reales verificados en Splunk.

### 🔴 Hallazgo 1 — SSRF / Bypass de Autenticación (CVE-2021-26855)

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:45:00 | **Recepción de alerta**: el SIEM dispara la Regla 1, severidad Alta/Crítica. | Disparador: patrón de bypass SSRF hacia `/autodiscover/`. Inicio formal del triage. |
| ~09:45:10 | **Enriquecimiento con VirusTotal**: se consulta la IP `103.77.192.219`. | **10 de 91 motores de seguridad** la marcan como maliciosa (ADMINUSLabs, alphaMountain.ai, Fortinet, Kaspersky, G-Data, Webroot, entre otros) — clasificaciones de Malicious, Phishing y Malware. Adicionalmente, esta IP está documentada como IOC de la campaña HAFNIUM en el advisory oficial **CISA AA21-062A**. Verdadero Positivo confirmado con dos fuentes independientes. |
| ~09:45:30 | **Análisis forense de la URI**: inspección de `cs_uri_stem` y `cs_uri_query` en los logs de IIS. | Se aísla la cadena: `/autodiscover/autodiscover.json` con query `@update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net` — sintaxis `@` que confunde al parser de Exchange, forzando al servidor a autenticarse ante sí mismo sin credenciales. |

**QUÉ DECIR sobre el enriquecimiento (con el número correcto):**
> *"Consultamos la IP en VirusTotal y confirmamos 10 de 91 motores de seguridad marcándola como
> maliciosa — esto lo verificamos en vivo, no es un dato inventado. Y no es una IP cualquiera:
> aparece documentada como indicador de compromiso de la campaña HAFNIUM en el advisory conjunto de
> CISA, AA21-062A."*

### 🔴 Hallazgo 2 — Escritura de Webshell (CVE-2021-27065)

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:46:05 | **Identificación del payload de escritura**: se detecta `POST /ecp/proxyLogon.ecp`, `time_taken=340ms` (anómalamente alto). | El atacante abusó del cmdlet legítimo `Set-OabVirtualDirectory` para forzar la escritura de un archivo en el directorio público del servidor. |
| 09:46:20 | **Confirmación de persistencia**: `GET /owa/auth/help.aspx`, respuesta `200 OK`. | El atacante valida que su webshell está activo. `help.aspx` coincide con nombres reales documentados de la campaña HAFNIUM. |

**🎯 El argumento forense más fuerte de todo el triage — dilo así, textual:**
> *"Profesor, un punto crucial aquí es que estamos ante una cadena de explotación (exploit chain).
> CVE-2021-26855 es una vulnerabilidad **pre-autenticación** — el atacante no necesita usuario ni
> clave. CVE-2021-27065, en cambio, es **post-autenticación** — bajo condiciones normales, solo un
> administrador con credenciales válidas podría escribir archivos en esos directorios de Exchange.
> Si nuestro SIEM detecta que una IP externa, sin ninguna autenticación previa registrada, logró
> activar CVE-2021-27065 para escribir la webshell, eso **demuestra implícitamente** que
> CVE-2021-26855 ya se explotó exitosamente como puente para saltarse la autenticación. Una fase no
> puede existir sin la otra en este tipo de incidente — es el argumento forense que confirma la
> cadena completa sin necesitar ver cada paso intermedio por separado."*

### 🔴 Hallazgo 3 — Ejecución de Comandos (Comando y Control)

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:46:46 - 09:51:01 | **Pivote hacia telemetría del host** (EXCH01): se revisan los Windows Event Logs correlacionados con la actividad web. | Se confirma el árbol de proceso anómalo `w3wp.exe → cmd.exe` / `w3wp.exe → powershell.exe`, ejecutando `whoami` (09:46:46), `ipconfig /all` (09:47:41), `net user` (09:49:06), y un comando PowerShell codificado en Base64 (09:51:01). |
| — | **Validación cruzada con OTRF**: se compara el patrón contra el dataset público real. | Coincidencia exacta del patrón `w3wp.exe → cmd.exe` con una ejecución real y documentada del exploit — Regla 6. |

**Sobre el comando PowerShell codificado, si preguntan:**
> *"El flag `-enc` de PowerShell ejecuta un comando codificado en Base64 — una técnica de evasión
> documentada: dificulta que una inspección superficial de logs identifique la intención real sin
> decodificarlo primero. Es consistente con el uso del framework ofensivo Nishang, documentado en
> reportes públicos de esta campaña."*

### 🔴 Hallazgo 4 — Abuso de Funcionalidad de Exchange (Exfiltración, preparación)

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:52:00 | **Auditoría de PowerShell Script Block Log** (EventCode 4104). | El atacante ejecutó `New-MailboxExportRequest -Mailbox jgarcia -FilePath ...\aspnet_client\backup.pst` — un cmdlet legítimo, abusado para exportar el buzón completo hacia una carpeta pública del servidor web. |

### 🔴 Hallazgo 5 — Acceso a Memoria / Robo de Credenciales

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:53:30 | **Detección de acceso anómalo a LSASS** (Sysmon-style EventCode 10). | `procdump.exe`, ejecutándose desde `C:\Windows\Temp\` (ubicación atípica), abre un handle de lectura hacia `lsass.exe` con `GrantedAccess=0x1410`. Técnica MITRE ATT&CK T1003.001. El incidente escala a compromiso total del servidor. |

### 🛑 Cierre del triage — Exfiltración confirmada

| Hora (UTC) | Acción del analista | Resultado |
|---|---|---|
| 09:54:15 | **Confirmación de descarga de datos**: `GET /aspnet_client/backup.pst`, `time_taken=5200ms`. | Transferencia de tamaño y duración anómalos — confirma que la exfiltración se completó. Fin del triage técnico. |

### Categorización y prioridad final
> *"Falso Positivo: descartado por completo — ninguna combinación de tráfico legítimo explica esta
> secuencia. Verdadero Positivo: confirmado con alta confianza, respaldado por dos fuentes de log
> independientes, enriquecimiento externo en VirusTotal, y validación cruzada contra un dataset real.
> Severidad: Crítica — servidor de correo de producción comprometido con ejecución remota de código
> y exfiltración de datos confirmadas. Se escala inmediatamente a Nivel 2 para activar el plan de
> respuesta al incidente."*

**Nota importante sobre el cierre — qué SÍ decir y qué NO decir:**
No mencionen un "Playbook SOAR" ni un sistema de tickets tipo Jira como si lo hubieran implementado
— nuestro proyecto es SIEM únicamente. Lo correcto es decir:
> *"A partir de aquí se activa el plan de respuesta al incidente que detallamos en el análisis
> técnico — bloqueo de la IP en el firewall, aislamiento del servidor, rotación de credenciales, y
> escalamiento al equipo de respuesta a incidentes. La automatización de esta respuesta vía una
> plataforma SOAR queda documentada como una recomendación para producción, fuera del alcance que
> elegimos para este proyecto — priorizamos profundidad en la detección SIEM."*

---

## Resumen de qué cambió respecto a lo que pegaste

| Dato original | Problema | Corrección aplicada |
|---|---|---|
| VirusTotal 42/89 | No coincide con la captura real (10/91) | Usar 10/91, verificado |
| "VT etiquetó como infraestructura Hafnium" | VirusTotal no hace esa atribución directa | Separar: VT confirma maliciosa; CISA AA21-062A confirma la atribución a HAFNIUM |
| Timestamps ligeramente distintos (09:47:00, 09:51:20, 09:52:45, 09:54:30) | No coinciden exactamente con los datos indexados en Splunk | Ajustados a los timestamps reales verificados |
| "EDR corporativo", "SOAR Incident Playbook", "Jira-SOC System #9942" | Contradice que el proyecto es solo SIEM (rúbrica: "escoger uno") | Reformulado como recomendación para producción, no como algo ejecutado |
| Lógica CVE-2021-26855 ↔ CVE-2021-27065 | — | Se mantuvo casi textual, es un argumento sólido y correcto |
