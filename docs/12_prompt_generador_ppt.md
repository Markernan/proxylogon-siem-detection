# Prompt para generar la presentación (Gamma.app recomendado)

**Herramienta recomendada**: [Gamma.app](https://gamma.app), opción **"Paste in text"** (no
"Generate from prompt" corto). Gamma respeta la estructura de slides y no recorta datos técnicos
como sí tiende a hacer Canva Magic Design. Alternativa: Tome.app.

**Cómo usarlo**: copia TODO el bloque de abajo (desde `TÍTULO DEL DECK` hasta el final) y pégalo
directamente en el campo de texto de Gamma al crear un nuevo deck con "Paste in text".

---

```
TÍTULO DEL DECK: Detección del Ataque ProxyLogon mediante SIEM — Corporación Financiera del Pacífico S.A.
AUDIENCIA: Profesor universitario de ciberseguridad, evaluación formal de 15 minutos + ronda de preguntas de 15 minutos
TONO: Profesional, técnico, estilo centro de operaciones de seguridad (SOC) — preciso, sin relleno
IDIOMA: Español (Perú)

INSTRUCCIONES DE DISEÑO:
- Tema claro tipo terminal/SIEM: fondo  claro o azul con blanco, texto negro
- Código de colores consistente en todo el deck: ROJO para severidad Crítica, ÁMBAR para Alta, VERDE para confirmado/resuelto/falso-positivo-descartado, AZUL para información neutra
- Fragmentos de código SPL o campos de log en bloques de código con fuente monoespaciada
- Preferir tablas y bullets cortos sobre párrafos largos — máximo 6 líneas de contenido visible por slide
- Dejar exactamente 3 slides marcados como "[PLACEHOLDER — CAPTURA DE PANTALLA REAL DE SPLUNK, insertar después]" en los puntos indicados más abajo — no generar contenido inventado ahí, solo el marcador y el título del slide
- Usar un ícono o color distintivo por fase del Cyber Kill Chain para dar continuidad visual entre slides (ej. lupa=reconocimiento, llave=explotación, engranaje=instalación, terminal=C2, salida=exfiltración)
- Cada tabla de datos debe reproducirse EXACTAMENTE con los números que doy abajo — no redondear ni inventar cifras adicionales

=====================================================
SLIDE 1 — PORTADA
=====================================================
Título: Detección del Ataque ProxyLogon mediante SIEM
Subtítulo: Análisis técnico y simulación de detección — Corporación Financiera del Pacífico S.A. (CFP)
Curso: Temas Avanzados en Optimización y Seguridad (TEL154)
Integrantes: [nombres]
Pie: Splunk Enterprise 10.4.1 | CVE-2021-26855 · CVE-2021-26857 · CVE-2021-26858 · CVE-2021-27065

=====================================================
SLIDE 2 — POR QUÉ ESTE ATAQUE
=====================================================
Título: ProxyLogon — Contexto General
- Cadena de 4 CVEs en Microsoft Exchange Server, explotada activamente desde enero de 2021 (antes de existir parche)
- Divulgado por Microsoft el 2 de marzo de 2021, atribuido al grupo HAFNIUM (vinculado a China, patrocinado por el Estado)
- Más de 250,000 servidores Exchange comprometidos mundialmente — uno de los incidentes más grandes de 2021
- Investigado originalmente por Volexity ("Operation Exchange Marauder"), ampliado por Microsoft MSTIC y CISA (advisory conjunto AA21-062A)
- Elegido por tener fuentes primarias verificables y públicas, no un caso hipotético sin sustento

=====================================================
SLIDE 3 — LA ORGANIZACIÓN HIPOTÉTICA: CFP
=====================================================
Título: Corporación Financiera del Pacífico S.A. (CFP)
- Entidad financiera peruana regulada, ~850 empleados, 30 agencias a nivel nacional
- Servidor Exchange on-premise (EXCH01.cfp-financiera.local) expuesto a internet desde 2019 para que la fuerza comercial accediera a correo sin depender de VPN completa
- Activo clasificado como CRÍTICO: buzones con datos financieros y personales de clientes (Ley N.° 29733 de Protección de Datos Personales)
- Entidad regulada por la Superintendencia de Banca, Seguros y AFP (SBS)
- Sector financiero confirmado como efectivamente afectado en la campaña real (reporte de ESET: 10 grupos APT distintos explotaron esta vulnerabilidad)

=====================================================
SLIDE 4 — CYBER KILL CHAIN: LAS 7 FASES
=====================================================
Título: Cyber Kill Chain de ProxyLogon
Diagrama de flujo horizontal con 7 cajas conectadas por flechas:
1. Reconocimiento — Escaneo externo buscando Exchange vulnerable
2. Weaponización — Construcción del payload SSRF + webshell
3. Entrega — Petición HTTP directa al puerto 443 expuesto
4. Explotación — CVE-2021-26855 (SSRF, bypass de autenticación)
5. Instalación — CVE-2021-27065 (escritura del webshell)
6. Comando y Control — Ejecución de comandos vía el webshell
7. Acciones sobre los Objetivos — Robo de credenciales + exfiltración

=====================================================
SLIDE 5 — VULNERABILIDADES EXPLOTADAS
=====================================================
Título: Los 4 CVEs de la Cadena "ProxyLogon"
Tabla:
| CVE | Componente | Tipo | CVSS | Rol |
| CVE-2021-26855 | Client Access Service | SSRF pre-autenticación | 9.1 | Bypass de autenticación |
| CVE-2021-26857 | Unified Messaging | Deserialización insegura | 7.8 | Ejecución código SYSTEM |
| CVE-2021-26858 | Exchange (post-auth) | Escritura arbitraria de archivos | 7.8 | Vía alternativa de instalación |
| CVE-2021-27065 | ECP (post-auth) | Escritura arbitraria de archivos | 7.8 | Vía principal — instala el webshell |
Nota al pie: El nombre "ProxyLogon" describe el mecanismo — el atacante logra un proxy hacia un logon válido sin necesitar credenciales

=====================================================
SLIDE 6 — OPERACIÓN TÉCNICA: EL MECANISMO SSRF
=====================================================
Título: CVE-2021-26855 — Cómo Funciona el Bypass
- Exchange tiene arquitectura de 2 capas: frontend (Client Access Service) + backend interno
- El atacante envía una URI manipulada: /autodiscover/autodiscover.json con parámetro @dominio-externo
- Combinada con cookie falsificada: X-AnonResource-Backend=<backend>~<puerto>
- El frontend reenvía la petición al backend AUTENTICÁNDOSE COMO SI FUERA UN PROCESO DE CONFIANZA
- Resultado: acceso a cualquier buzón de correo sin usuario ni contraseña

=====================================================
SLIDE 7 — HERRAMIENTAS Y TÉCNICAS DOCUMENTADAS
=====================================================
Título: Arsenal Real de la Campaña HAFNIUM
- Scripts de escaneo masivo para reconocimiento a escala de internet
- Webshells ligeros tipo "China Chopper" (código ofuscado, ~1 línea)
- Framework ofensivo de PowerShell "Nishang"
- procdump.exe (Sysinternals, herramienta LEGÍTIMA de Microsoft) — técnica "living off the land"
- 7-Zip para compresión de datos exfiltrados
- New-MailboxExportRequest (cmdlet legítimo de Exchange, abusado)

=====================================================
SLIDE 8 — EVIDENCIA DIGITAL Y ARTEFACTOS
=====================================================
Título: 4 Categorías de Artefactos Digitales
Tabla:
| Categoría | Artefacto en ProxyLogon |
| Registros de eventos | EventCode 4688 (w3wp.exe → cmd.exe), EventCode 4104 (PowerShell ScriptBlock) |
| Archivos modificados | Webshell .aspx nuevo en carpeta de autenticación OWA (EventCode 4663) |
| Procesos sospechosos | procdump.exe desde C:\Windows\Temp\ accediendo a lsass.exe |
| Tráfico de red anómalo | time-taken de 8ms (automatizado); descarga de 5200ms (exfiltración) |

=====================================================
SLIDE 9 — EQUIPOS QUE PRODUCEN LA EVIDENCIA
=====================================================
Título: 4 Sistemas, 4 Roles en la Evidencia
- Servidor Exchange/IIS → logs W3C de todas las peticiones HTTP (Fuente 1)
- Sistema Operativo Windows → Security Event Log + PowerShell Operational Log (Fuente 2)
- Solución EDR/Antivirus → detectaría webshell y volcado de LSASS por comportamiento (brecha documentada, fuera de alcance)
- SIEM Splunk → consolida, correlaciona y genera las 7 alertas

=====================================================
SLIDE 10 — PLAN DE RESPUESTA AL INCIDENTE (NIST SP 800-61)
=====================================================
Título: 6 Fases de Respuesta
Diagrama de flujo: Preparación → Detección y Análisis → Contención → Erradicación → Recuperación → Comunicación Regulatoria
- Contención: bloquear IP 103.77.192.219 en firewall, eliminar webshell
- Erradicación: parche acumulativo o Exchange On-Premises Mitigation Tool (EOMT), rotar credenciales
- Comunicación regulatoria: notificación a SBS, Autoridad de Protección de Datos Personales (Ley 29733), clientes afectados

=====================================================
SLIDE 11 — [PLACEHOLDER — CAPTURA DE PANTALLA REAL DE SPLUNK, insertar después]
=====================================================
Título: Arquitectura de la Solución SIEM
(Texto guía para cuando se inserte la captura: Dashboard "ProxyLogon - Overview" mostrando el gráfico de picos de tráfico y los contadores de reglas)
- Índice Splunk "proxylogon": 296 eventos IIS + 32 eventos Windows Event Log
- 2 fuentes de log reales, cumpliendo el requisito mínimo de la rúbrica
- Tráfico benigno mezclado con el ataque (~280 eventos normales de empleados)

=====================================================
SLIDE 12 — LAS 7 REGLAS DE DETECCIÓN
=====================================================
Título: 7 Alertas, Cada Una una Fase del Kill Chain
Tabla:
| # | Alerta | Fase | Resultado |
| 01 | SSRF Autodiscover Bypass | Explotación | 7 eventos |
| 02 | Webshell Drop | Instalación | 2 eventos |
| 03 | C2 via Webshell | Comando y Control | 4 eventos |
| 04 | Mailbox Export | Acciones sobre objetivos | 1 evento |
| 05 | LSASS Access | Acciones sobre objetivos | 1 evento |
| 06 | Validación dataset real OTRF | Validación cruzada | 3 eventos |
| 07 | Prueba de Falsos Positivos | Control de calidad | 0 (confirmado) |

=====================================================
SLIDE 13 — REGLA 1: SSRF AUTODISCOVER BYPASS
=====================================================
Título: Detección de la Explotación (CVE-2021-26855)
Bloque de código SPL:
index=proxylogon sourcetype=iis (cs_uri_stem="*autodiscover*" OR cs_uri_stem="*/ecp/*")
(cs_uri_query="*@*" OR cs_Cookie="*X-AnonResource-Backend*")
| lookup hafnium_ips src_ip AS c_ip OUTPUT isBad AS ip_conocida_hafnium
- IP origen: 103.77.192.219 — IOC real documentado en CISA AA21-062A
- 7 eventos detectados, todos con ip_conocida_hafnium=TRUE
- time_taken=8ms — patrón de tráfico automatizado, no humano

=====================================================
SLIDE 14 — REGLA 6: VALIDACIÓN CON EJECUCIÓN REAL DEL EXPLOIT
=====================================================
Título: No Solo Simulación — Validado Contra Datos Reales
- Dataset público de OTRF (Open Threat Research Forge): 28 eventos Sysmon reales
- Capturados el 14 de marzo de 2021 al ejecutar el exploit público de ProxyLogon en un laboratorio real
- Mismo patrón encontrado: w3wp.exe generando cmd.exe con "whoami"
- Conclusión: nuestras reglas detectarían el ataque real, no solo la simulación

=====================================================
SLIDE 15 — REGLA 7: PRUEBA DE FALSOS POSITIVOS
=====================================================
Título: Confirmando que NO es un Falso Positivo
- Requisito explícito del profesor en la aprobación de la propuesta
- Misma lógica de la Regla 1, filtrada solo a tráfico interno benigno (192.168.1.x)
- Resultado: 0 falsos positivos — evidencia cuantitativa, no solo afirmación
- De ~280 eventos benignos generados, ninguno coincide con el patrón de ataque

=====================================================
SLIDE 16 — [PLACEHOLDER — CAPTURA DE PANTALLA REAL DE SPLUNK, insertar después]
=====================================================
Título: Línea de Tiempo Completa del Ataque
(Texto guía: Dashboard "ProxyLogon - Detalle por Fase", panel de línea de tiempo con las 9 etapas)
Tabla de referencia (para que el diseño la use como base):
| Hora | Etapa |
| 09:12 | Reconocimiento |
| 09:45 | Explotación (SSRF) |
| 09:46 | Instalación (webshell) |
| 09:46-09:51 | Comando y Control |
| 09:52 | Exportación de buzón |
| 09:53 | Acceso a LSASS |
| 09:54 | Exfiltración |
Duración total: 42 minutos 15 segundos

=====================================================
SLIDE 17 — PLAN DE TRIAGE: MTTD Y TIEMPO DE RESPUESTA
=====================================================
Título: De la Detección a la Decisión — Métricas Reales
Tabla:
| Métrica | Valor |
| Duración total del ataque | 42 min 15 seg |
| MTTD (evento → alerta Splunk) | ~5 segundos |
| Tiempo de trabajo humano del analista | ~13.5 minutos |
| Ventana real de contención | 9 min 10 seg (antes de la exfiltración) |
Cita destacada: "Sin un SIEM, reconstruir esta cadena manualmente tomaría horas, no minutos"

=====================================================
SLIDE 18 — [PLACEHOLDER — CAPTURA DE PANTALLA REAL DE VIRUSTOTAL, insertar después]
=====================================================
Título: Enriquecimiento con Threat Intelligence
(Texto guía: captura de VirusTotal para la IP 103.77.192.219)
- 10 de 91 motores de seguridad marcan la IP como maliciosa
- Clasificaciones: Malicious, Phishing, Malware (ADMINUSLabs, Fortinet, Kaspersky, G-Data, Webroot, entre otros)
- IP documentada como IOC real de HAFNIUM en el advisory CISA AA21-062A

=====================================================
SLIDE 19 — ARGUMENTO FORENSE: LA CADENA QUE SE AUTO-CONFIRMA
=====================================================
Título: Por Qué un Hallazgo Confirma al Otro
- CVE-2021-26855 = vulnerabilidad PRE-autenticación (sin usuario ni clave)
- CVE-2021-27065 = vulnerabilidad POST-autenticación (requiere sesión válida)
- Si una IP externa sin autenticación previa activó CVE-2021-27065 (escribió el webshell), esto DEMUESTRA que CVE-2021-26855 ya se explotó exitosamente como puente
- Una fase no puede existir sin la otra en este tipo de incidentea

=====================================================
SLIDE 20 — LÍMITES Y ALCANCE DE LA   SOLUCIÓN
=====================================================
Título: Lo Que Cubrimos y Lo Que No (Honestidad Técnica)
Cubre: detección basada en comportamiento, 2 fuentes de log, enriquecimiento externo, correlación temporal
No cubre: tercera fuente de red (firewall/NetFlow), EDR real, UEBA/análisis de comportamiento, variantes desconocidas del ataque, respuesta automatizada (SOAR — fuera del alcance elegido)

=====================================================
SLIDE 21 — CONCLUSIONES
=====================================================
Título: Resumen del Proyecto
- Analizamos las 7 fases del Cyber Kill Chain de un ataque real y documentado
- Identificamos los artefactos digitales de cada fase con equipos y fuentes específicas
- Implementamos 7 reglas de detección en Splunk sobre 2 fuentes de log reales
- Validamos las reglas contra una ejecución genuina y pública del exploit
- Confirmamos cuantitativamente la ausencia de falsos positivos
- Diseñamos un plan de respuesta alineado a NIST y a la normativa financiera peruana

=====================================================
SLIDE 22 — CIERRE
=====================================================
Título: Preguntas
Subtítulo: Quedamos atentos a su retroalimentación
Pie: Corporación Financiera del Pacífico S.A. | Splunk Enterprise | ProxyLogon (CVE-2021-26855 et al.)
```

---

## Después de generar el deck en Gamma

1. **Reemplaza los 3 slides con `[PLACEHOLDER]`** (11, 16, 18) con capturas de pantalla reales de tu Splunk y de VirusTotal — no dejes el placeholder en la versión final.
2. Ajusta el número de slides si el tiempo no calza al ensayar — es más fácil recortar que armar de cero.
3. Revisa que Gamma no haya alterado ningún número (score de VirusTotal, timestamps, cifras de las reglas) — a veces las IAs "redondean" datos por su cuenta.
