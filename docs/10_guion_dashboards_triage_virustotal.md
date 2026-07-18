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

## PARTE 3 — Plan de Triage y Confirmación (versión expandida, con evidencia y tiempos humanos)

Estructura: 5 hallazgos + cierre, con el **Analista SOC Nivel 1** como rol narrador. Cada hallazgo
distingue **3 relojes distintos** — no los confundas al presentar:

1. **Hora del evento** (`Hora Evento`): cuándo ocurrió realmente en el ataque — esto es fijo, sale
   del log, no cambia.
2. **Hora de alerta** (`Hora Alerta`): cuándo Splunk efectivamente generó la alerta correlacionando
   ese evento — en nuestra configuración de demo, casi inmediato (segundos), porque las reglas
   corren sobre datos ya indexados; en un SOC de producción real, depende de la frecuencia del
   cron del scheduler (nosotros documentamos las reglas con evaluación cada 5 minutos como
   referencia realista de producción).
3. **Tiempo de analista** (`⏱️ Analista`): cuánto le toma al ser humano —no al sistema— revisar,
   pivotar y confirmar cada hallazgo. Este es el dato que conecta con las métricas de **MTTD (Mean
   Time to Detect)** y **MTTR (Mean Time to Respond)** vistas en el curso como responsabilidad del
   SOC Manager.

> *"Antes de entrar al detalle, quiero destacar algo: vamos a distinguir el tiempo que tardó el
> ataque en ejecutarse, el tiempo que tardó Splunk en generar la alerta, y el tiempo que le toma a
> un analista humano investigarla — son tres velocidades distintas, y esa distinción es
> precisamente lo que mide el MTTD y el MTTR de un SOC."*

### 🔴 Hallazgo 1 — SSRF / Bypass de Autenticación (CVE-2021-26855)

| Reloj | Valor |
|---|---|
| Hora Evento | 09:45:00 (primera de 6 peticiones SSRF, hasta 09:45:45) |
| Hora Alerta | 09:45:05 (Splunk correlaciona y dispara la Regla 1) |
| **MTTD** (evento → alerta) | **~5 segundos** |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta (fuente + campos) | Resultado |
|---|---|---|---|
| Recepción de alerta crítica | instantáneo | Regla 1 disparada, severidad Alta/Crítica | Inicio formal del triage — el analista abre el caso |
| Enriquecimiento con VirusTotal | **~1 min** | Consulta manual a `virustotal.com/gui/ip-address/103.77.192.219` | **10 de 91 motores** marcan la IP como maliciosa (Malicious/Phishing/Malware). Adicionalmente documentada como IOC de HAFNIUM en **CISA AA21-062A** |
| Análisis forense de la URI | **~2 min** | **Fuente**: `sourcetype=iis` · **Campos**: `_time`, `c_ip`, `cs_uri_stem`, `cs_uri_query`, `sc_status`, `time_taken` | Se aísla la cadena `@update-cdn-svc.net/mapi/nspi/?&Email=...` — sintaxis que confunde al parser de Exchange. `sc_status=241` (código interno no estándar), `time_taken=8ms` (demasiado rápido para un cliente humano) |
| Correlación con lookup de IOCs | **~30 seg** | **Fuente**: lookup `hafnium_ips` vía comando `lookup hafnium_ips src_ip AS c_ip` | Campo `ip_conocida_hafnium=TRUE` en las 7 filas — confirmación automatizada, no solo apreciación del analista |
| **Subtotal Hallazgo 1** | **~3.5 min de trabajo humano** | | |

### 🔴 Hallazgo 2 — Escritura de Webshell (CVE-2021-27065)

| Reloj | Valor |
|---|---|
| Hora Evento | 09:46:05 (POST) → 09:46:20 (GET de confirmación) |
| Hora Alerta | 09:46:08 |
| **MTTD** | **~3 segundos** |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta | Resultado |
|---|---|---|---|
| Identificación del payload de escritura | **~1 min** | **Fuente**: `sourcetype=iis` · **Campos**: `cs_method=POST`, `cs_uri_stem=/ecp/proxyLogon.ecp`, `sc_status=200`, `time_taken=340` | `time_taken` anómalamente alto (340ms vs 8ms de las peticiones SSRF) — consistente con una operación de escritura en disco, no una simple consulta |
| Confirmación de persistencia | **~30 seg** | **Fuente**: `sourcetype=iis` · **Campos**: `cs_method=GET`, `cs_uri_stem=/owa/auth/help.aspx`, `sc_status=200` | El atacante confirma que su webshell quedó accesible. `help.aspx` coincide con nombres reales documentados de la campaña HAFNIUM (fuente: repositorio de IOCs compilado por Splunk) |
| **Subtotal Hallazgo 2** | **~1.5 min de trabajo humano** | | |

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

| Reloj | Valor |
|---|---|
| Hora Evento | 09:46:46 (primer comando) → 09:51:01 (último, PowerShell codificado) |
| Hora Alerta | 09:46:49 (se dispara con el primer `whoami`) |
| **MTTD** | **~3 segundos** desde el primer comando |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta | Resultado |
|---|---|---|---|
| Pivote hacia telemetría del host (EXCH01) | **~2 min** | **Fuente**: `sourcetype=windows_events_proxylogon`, `EventCode=4688` · **Campos**: `Computer`, `NewProcessName`, `ParentProcessName`, `CommandLine` | Árbol de proceso anómalo `w3wp.exe → cmd.exe` (3 veces: `whoami` 09:46:46, `ipconfig /all` 09:47:41, `net user` 09:49:06) y `w3wp.exe → powershell.exe` (09:51:01) |
| Decodificación del comando ofuscado | **~1.5 min** | **Campo**: `CommandLine` conteniendo `powershell.exe /c powershell -enc JABjAGwAaQBlAG4AdAA...` | El flag `-enc` indica Base64 — técnica de evasión documentada; consistente con el uso del framework ofensivo Nishang reportado en la campaña real |
| Validación cruzada con dataset OTRF | **~1 min** | **Fuente**: `sourcetype=json_otrf_real`, `EventID=1` · **Campo**: `ParentImage="*w3wp*"` | Coincidencia exacta del patrón `w3wp.exe → cmd.exe` con una ejecución real y pública del exploit — Regla 6 |
| **Subtotal Hallazgo 3** | **~4.5 min de trabajo humano** | | |

### 🔴 Hallazgo 4 — Abuso de Funcionalidad de Exchange (preparación de exfiltración)

| Reloj | Valor |
|---|---|
| Hora Evento | 09:52:00 |
| Hora Alerta | 09:52:02 |
| **MTTD** | **~2 segundos** |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta | Resultado |
|---|---|---|---|
| Auditoría de PowerShell Script Block Log | **~1.5 min** | **Fuente**: `sourcetype=windows_events_proxylogon`, `EventCode=4104` · **Campo**: `ScriptBlockText` | Contenido completo capturado: `New-MailboxExportRequest -Mailbox 'jgarcia' -FilePath '\\EXCH01\C$\inetpub\wwwroot\aspnet_client\backup.pst'` — cmdlet legítimo, abusado para exportar el buzón hacia una carpeta pública del servidor web |
| **Subtotal Hallazgo 4** | **~1.5 min de trabajo humano** | | |

### 🔴 Hallazgo 5 — Acceso a Memoria / Robo de Credenciales

| Reloj | Valor |
|---|---|
| Hora Evento | 09:53:30 |
| Hora Alerta | 09:53:32 |
| **MTTD** | **~2 segundos** |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta | Resultado |
|---|---|---|---|
| Detección de acceso anómalo a LSASS | **~1 min** | **Fuente**: `sourcetype=windows_events_proxylogon`, `EventCode=10` · **Campos**: `SourceProcessName`, `TargetProcessName`, `GrantedAccess` | `procdump.exe` (ejecutándose desde `C:\Windows\Temp\`, ubicación atípica) abre un handle hacia `lsass.exe` con `GrantedAccess=0x1410` — permiso de lectura de memoria. Técnica MITRE ATT&CK T1003.001 |
| **Subtotal Hallazgo 5** | **~1 min de trabajo humano** | | |

### 🛑 Cierre del triage — Exfiltración confirmada

| Reloj | Valor |
|---|---|
| Hora Evento | 09:54:15 |
| Hora Alerta | — (este evento se identifica en la investigación del Hallazgo 4/5, no tiene regla dedicada) |

| Paso del analista | ⏱️ Tiempo | Evidencia exacta | Resultado |
|---|---|---|---|
| Confirmación de descarga de datos | **~30 seg** | **Fuente**: `sourcetype=iis` · **Campos**: `cs_uri_stem=/aspnet_client/backup.pst`, `cs_method=GET`, `time_taken=5200` | `time_taken` de 5200ms — muy superior al resto del tráfico, consistente con la transferencia de un archivo grande. Confirma que la exfiltración se completó |
| Decisión de categorización y escalamiento | **~1 min** | Síntesis de todo lo anterior | Verdadero Positivo, prioridad Crítica, escalamiento a Nivel 2 |
| **Subtotal Cierre** | **~1.5 min de trabajo humano** | | |

---

### 📊 Resumen de tiempos — el dato que más impacta si lo explicas bien

| Métrica | Valor | Qué significa |
|---|---|---|
| **Duración total del ataque** (evento a evento, reconocimiento → exfiltración) | 09:12:00 → 09:54:15 = **42 min 15 seg** | Cuánto le tomó al atacante completar toda la cadena |
| **MTTD por hallazgo** (evento → alerta de Splunk) | **2 a 5 segundos** en cada caso | El SIEM detecta casi en tiempo real porque las reglas ya están correlacionando continuamente sobre los datos indexados |
| **Tiempo total de trabajo humano** (suma de todos los subtotales de analista) | 3.5 + 1.5 + 4.5 + 1.5 + 1 + 1.5 = **~13.5 minutos** | Cuánto tiempo activo de investigación necesita un analista Nivel 1 para confirmar la cadena completa, de principio a fin |
| **Ventana de contención real** | Desde la primera alerta (09:45:05) hasta la exfiltración (09:54:15) = **9 minutos 10 segundos** | El tiempo que un SOC real tendría disponible para contener el ataque *antes* de que el atacante lograra exfiltrar datos, si actuara sobre la primera alerta de inmediato |

**QUÉ DECIR con este resumen (es tu cierre más fuerte de toda la sección de triage):**
> *"Esta tabla es importante porque separa tres cosas que normalmente se confunden: el ataque tomó
> 42 minutos en total, pero el SIEM detectó cada fase en cuestión de segundos — eso es el MTTD, el
> Mean Time to Detect, una métrica que el SOC Manager monitorea constantemente según lo que vimos en
> el curso. Sin embargo, confirmar la cadena completa con evidencia sólida —no solo reaccionar a la
> primera alerta, sino investigarla con enriquecimiento y correlación— le toma a un analista humano
> cerca de 13 minutos y medio de trabajo activo. Y ahí está el dato más importante: la primera
> alerta salta 9 minutos antes de que el atacante lograra exfiltrar cualquier dato. Esa es la
> ventana real de contención — si el analista prioriza correctamente y actúa sobre la Regla 1 de
> inmediato, en vez de esperar a investigar todo antes de contener, hay margen real para evitar la
> exfiltración. Sin un SIEM, reconstruir esta misma cadena manualmente —revisando logs crudos de dos
> sistemas distintos sin correlación automática— tomaría horas, no minutos, y probablemente se
> descubriría después de que el daño ya estuviera hecho."*

### Categorización y prioridad final
> *"Falso Positivo: descartado por completo — ninguna combinación de tráfico legítimo explica esta
> secuencia, y lo confirmamos cuantitativamente con la Regla 7 (0 falsos positivos contra tráfico
> interno benigno). Verdadero Positivo: confirmado con alta confianza, respaldado por dos fuentes de
> log independientes, enriquecimiento externo en VirusTotal, correlación automatizada contra IOCs
> reales, y validación cruzada contra un dataset real de ejecución del exploit. Severidad: Crítica —
> servidor de correo de producción comprometido con ejecución remota de código y exfiltración de
> datos confirmadas. Se escala inmediatamente a Nivel 2 para activar el plan de respuesta al
> incidente."*

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
