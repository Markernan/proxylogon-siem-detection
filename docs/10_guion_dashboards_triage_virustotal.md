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

## PARTE 3 — Plan de Triage y Confirmación (formato de bitácora — Timestamp / Analista / Acción / Justificación / Evidencia)

**Analista**: [Nombre] — Analista SOC Nivel 1, Corporación Financiera del Pacífico S.A.

Cada fila distingue, dentro de la columna "Acción Tomada / Observación", el **tiempo que le toma al
analista humano** completar ese paso (no confundir con la hora del evento, que es fija y sale del
log). Esto conecta con las métricas de **MTTD (Mean Time to Detect)** y **MTTR (Mean Time to
Respond)** que el curso ubica como responsabilidad del SOC Manager.

> *"Antes de entrar al detalle, quiero destacar algo: vamos a distinguir el tiempo que tardó el
> ataque en ejecutarse, el tiempo que tardó Splunk en generar la alerta, y el tiempo que le toma a
> un analista humano investigarla — son tres velocidades distintas."*

### 💉 Hallazgo 1 — SSRF / Bypass de Autenticación (CVE-2021-26855)

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:45:05 | [Nombre] | **Recepción de alerta inicial** (instantáneo): el SIEM dispara la Regla 1, severidad Alta/Crítica, 5 segundos después del primer evento real (09:45:00). | MTTD ≈ 5 segundos. Inicio formal del triage — se abre el caso. | 🔴 Alerta 01 — SIEM Dashboard |
| 09:46:05 | [Nombre] | **Verificación reputacional en VirusTotal** (⏱️ ~1 min): se extrae la IP origen `103.77.192.219` y se consulta en `virustotal.com/gui/ip-address/103.77.192.219`. | **10 de 91 motores de seguridad** la marcan como maliciosa (Malicious/Phishing/Malware — ADMINUSLabs, alphaMountain.ai, Fortinet, Kaspersky, G-Data, Webroot, entre otros). Adicionalmente, documentada como IOC de la campaña HAFNIUM en el advisory oficial **CISA AA21-062A**. Verdadero Positivo confirmado con dos fuentes independientes. | API/Web VirusTotal — IP: 103.77.192.219 — Status: Malicious |
| 09:48:05 | [Nombre] | **Análisis forense de la petición web** (⏱️ ~2 min): inspección de la URI y parámetros crudos en los logs de IIS. | Se aísla la cadena de inyección: `/autodiscover/autodiscover.json` con query `@update-cdn-svc.net/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@update-cdn-svc.net`. El atacante insertó una sintaxis con `@` para confundir al parser de Exchange, obligando al servidor a autenticarse ante sí mismo sin credenciales. `sc_status=241` (código interno no estándar), `time_taken=8ms` (demasiado rápido para un cliente humano). | IIS Logs — Fields: `cs_uri_stem`, `cs_uri_query`, `sc_status`, `time_taken` |
| 09:50:05 | [Nombre] | **Correlación automatizada con lookup de IOCs** (⏱️ ~30 seg): se cruza la IP contra la tabla de amenazas reales. | Campo `ip_conocida_hafnium=TRUE` en las 7 filas — confirmación automatizada vía `lookup hafnium_ips`, no solo apreciación manual del analista. | Splunk lookup — `hafnium_ips.csv` |

**Subtotal Hallazgo 1: ~3.5 minutos de trabajo activo del analista.**

### 💉 Hallazgo 2 — Escritura Arbitraria de Archivos / Webshell Drop (CVE-2021-27065)

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:46:08 | [Nombre] | **Identificación del payload de escritura** (⏱️ ~1 min): monitoreo del flujo de eventos subsiguientes al bypass exitoso. | Se detecta `POST /ecp/proxyLogon.ecp`, `sc_status=200`, `time_taken=340ms` — anómalamente alto (vs 8ms de las peticiones SSRF), consistente con una operación de escritura en disco. El atacante abusó del cmdlet legítimo `Set-OabVirtualDirectory`, accesible vía ECP, para forzar la escritura del webshell. | 🔴 Alerta 02 — IIS Logs — Method: POST |
| 09:46:20 | [Nombre] | **Confirmación de persistencia** (⏱️ ~30 seg): monitoreo de la solicitud de verificación del propio atacante. | `GET /owa/auth/help.aspx`, respuesta `200 OK`. El atacante valida que su puerta trasera está activa y expuesta a internet. `help.aspx` coincide con nombres de archivo reales documentados de la campaña HAFNIUM (repositorio de IOCs compilado por Splunk a partir de Volexity/Microsoft/Huntress Labs). | IIS Logs — Method: GET |

**Subtotal Hallazgo 2: ~1.5 minutos de trabajo activo del analista.**

**🎯 El argumento forense más fuerte de todo el triage — dilo así, textual, justo después de esta tabla:**
> *"Profesor, un punto crucial aquí es que estamos ante una cadena de explotación (exploit chain).
> CVE-2021-26855 es una vulnerabilidad **pre-autenticación** — el atacante no necesita usuario ni
> clave. CVE-2021-27065, en cambio, es **post-autenticación** — bajo condiciones normales, solo un
> administrador con credenciales válidas podría escribir archivos en esos directorios de Exchange.
> Si nuestro SIEM detecta que una IP externa, sin ninguna autenticación previa registrada, logró
> activar CVE-2021-27065 para escribir la webshell, eso **demuestra implícitamente** que
> CVE-2021-26855 ya se explotó exitosamente como puente para saltarse la autenticación. Una fase no
> puede existir sin la otra en este tipo de incidente."*

### 💉 Hallazgo 3 — Inyección de Comandos de Sistema Operativo (Comando y Control)

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:46:49 | [Nombre] | **Análisis forense de procesos en el host** (⏱️ ~2 min): pivotaje hacia la telemetría del endpoint EXCH01 para evaluar la actividad derivada del servidor web. | Se verifica el árbol de proceso anómalo `w3wp.exe → cmd.exe` / `w3wp.exe → powershell.exe`, ejecutando con privilegios elevados las sentencias de reconocimiento: `whoami` (09:46:46), `ipconfig /all` (09:47:41), `net user` (09:49:06). | 🔴 Alerta 03 — Windows EventCode 4688 — Fields: `NewProcessName`, `ParentProcessName`, `CommandLine` |
| 09:52:31 | [Nombre] | **Decodificación de comando ofuscado** (⏱️ ~1.5 min): extracción y análisis de la línea de comando de PowerShell con parámetros de evasión. | Se intercepta `powershell.exe /c powershell -enc JABjAGwAaQBlAG4AdAA...` (09:51:01). El flag `-enc` indica contenido codificado en Base64 — técnica de evasión documentada, consistente con el uso del framework ofensivo Nishang reportado en la campaña real. | Windows EventCode 4688 — Field: `CommandLine` |
| 09:54:01 | [Nombre] | **Validación cruzada contra dataset real OTRF** (⏱️ ~1 min): se compara el patrón contra una ejecución genuina y pública del exploit. | Coincidencia exacta del patrón `w3wp.exe → cmd.exe` con el dataset real capturado por OTRF en 2021 (`cmd /c whoami`) — Regla 6. Confirma que la regla detectaría el ataque real, no solo la simulación. | 🔴 Alerta 06 — `sourcetype=json_otrf_real`, `EventID=1` |

**Subtotal Hallazgo 3: ~4.5 minutos de trabajo activo del analista.**

### 💉 Hallazgo 4 — Abuso Funcional de Aplicación / Preparación de Exfiltración

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:55:31 | [Nombre] | **Evaluación de impacto sobre el servidor de correo** (⏱️ ~1.5 min): auditoría de las últimas acciones ejecutadas en Exchange vía el log de bloques de script de PowerShell. | Se identifica el robo de información corporativa: el cmdlet legítimo `New-MailboxExportRequest -Mailbox 'jgarcia' -FilePath '\\EXCH01\C$\inetpub\wwwroot\aspnet_client\backup.pst'` (evento real: 09:52:00) fue abusado para empaquetar el buzón completo del usuario crítico `jgarcia` y exportarlo al directorio web público, preparándolo para su descarga. | 🔴 Alerta 04 — PowerShell ScriptBlock Logs (EventCode 4104) |

**Subtotal Hallazgo 4: ~1.5 minutos de trabajo activo del analista.**

### 💉 Hallazgo 5 — Inyección en Memoria / Acceso a Procesos (Credential Dumping)

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:57:01 | [Nombre] | **Detección de compromiso de memoria LSASS** (⏱️ ~1 min): análisis del intento de escalamiento y robo de credenciales administrativas. | Se confirma el uso ilícito de `procdump.exe` operando de forma anómala desde `C:\Windows\Temp\` (evento real: 09:53:30). El binario abrió un handle de lectura (`GrantedAccess=0x1410`) hacia el proceso maestro `lsass.exe` para volcar credenciales en memoria (MITRE ATT&CK T1003.001). El incidente escala a **Compromiso Total del Servidor**. | 🔴 Alerta 05 — EventCode 10 (estilo Sysmon) — Target: `lsass.exe` |

**Subtotal Hallazgo 5: ~1 minuto de trabajo activo del analista.**

### 🛑 Fase Post-Inyección — Exfiltración Final y Cierre del Triage Técnico

| Timestamp (Hora UTC) | Analista | Acción Tomada / Observación | Justificación / Resultado | Evidencia (Ref.) |
|---|---|---|---|---|
| 09:58:01 | [Nombre] | **Confirmación de la descarga de datos** (⏱️ ~30 seg): rastreo final del tráfico saliente en los logs de IIS. | Se detecta `GET /aspnet_client/backup.pst` desde la IP del atacante (evento real: 09:54:15), `time_taken=5200ms` — muy superior al resto del tráfico, confirmando que el archivo `.pst` exfiltró la información corporativa con éxito. **Fin del triage técnico.** | IIS Logs — Fields: `cs_uri_stem`, `time_taken` |
| 09:58:31 | [Nombre] | **Categorización y decisión de escalamiento** (⏱️ ~1 min): síntesis de toda la evidencia recopilada. | Falso Positivo: descartado por completo (confirmado además cuantitativamente por la Regla 7, 0 FP contra tráfico interno). Verdadero Positivo: confirmado con alta confianza — 2 fuentes de log, enriquecimiento externo, correlación automatizada, validación cruzada real. Severidad: **Crítica**. Se escala inmediatamente a Nivel 2 para activar el plan de respuesta al incidente. | Síntesis de Hallazgos 1-5 |

**Subtotal Cierre: ~1.5 minutos de trabajo activo del analista.**

> **Nota sobre los timestamps de "Acción Tomada"**: a partir del Hallazgo 3 en adelante, los
> timestamps de columna 1 muestran el **momento en que el analista realiza cada acción de
> investigación** (acumulando el tiempo real de trabajo humano, uno detrás del otro, porque un
> analista no puede investigar dos hallazgos a la vez) — no el momento del evento del ataque en sí
> (ese va documentado dentro de la columna "Justificación / Resultado", entre paréntesis). Esto es
> intencional: refleja que, en la vida real, cuando llegan 5 alertas casi simultáneas, el analista
> las procesa en cola, una tras otra — es exactamente el fenómeno de "fatiga de alertas" que vimos
> en la teoría del curso.

---

### 📊 Resumen de tiempos — el dato que más impacta si lo explicas bien

| Métrica | Valor | Qué significa |
|---|---|---|
| **Duración total del ataque** (evento a evento, reconocimiento → exfiltración) | 09:12:00 → 09:54:15 = **42 min 15 seg** | Cuánto le tomó al atacante completar toda la cadena |
| **MTTD de la primera alerta** (evento → alerta de Splunk) | **~5 segundos** | El SIEM detecta casi en tiempo real porque las reglas ya están correlacionando continuamente sobre los datos indexados |
| **Tiempo total de trabajo humano** (suma de todos los subtotales de analista) | 3.5 + 1.5 + 4.5 + 1.5 + 1 + 1.5 = **~13.5 minutos** | Cuánto tiempo activo de investigación necesita un analista Nivel 1 para confirmar la cadena completa, de principio a fin, procesando las alertas en cola |
| **Ventana de contención real** | Desde la primera alerta (09:45:05) hasta la exfiltración (09:54:15) = **9 minutos 10 segundos** | El tiempo que un SOC real tendría disponible para contener el ataque *antes* de que el atacante lograra exfiltrar datos, si actuara sobre la primera alerta de inmediato en vez de esperar a completar todo el triage |

**QUÉ DECIR con este resumen (es tu cierre más fuerte de toda la sección de triage):**
> *"Esta tabla es importante porque separa tres cosas que normalmente se confunden: el ataque tomó
> 42 minutos en total, pero el SIEM detectó la primera fase en cuestión de segundos — eso es el
> MTTD, el Mean Time to Detect, una métrica que el SOC Manager monitorea constantemente según lo que
> vimos en el curso. Sin embargo, confirmar la cadena completa con evidencia sólida —procesando las
> alertas en cola, como ocurriría en un SOC real— le toma a un analista humano cerca de 13 minutos y
> medio de trabajo activo. Y ahí está el dato más importante: la primera alerta salta 9 minutos
> antes de que el atacante lograra exfiltrar cualquier dato. Esa es la ventana real de contención —
> si el analista prioriza correctamente y actúa sobre la Regla 1 de inmediato, en vez de esperar a
> investigar todo antes de contener, hay margen real para evitar la exfiltración. Sin un SIEM,
> reconstruir esta misma cadena manualmente —revisando logs crudos de dos sistemas distintos sin
> correlación automática— tomaría horas, no minutos, y probablemente se descubriría después de que
> el daño ya estuviera hecho."*

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
