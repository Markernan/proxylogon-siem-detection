# Falsos Positivos en la Vida Real, Alcance y Límites de la Solución

Nuestra Regla 7 demuestra que, **contra los datos de esta simulación**, hay 0 falsos positivos. Eso
es honesto pero incompleto: en un entorno de producción real, con años de tráfico administrativo
variado, varias de nuestras reglas **sí generarían ruido**. Reconocerlo — y explicar cómo se
resolvería — demuestra más madurez técnica que afirmar una precisión perfecta que no existe en la
práctica de ningún SIEM real. Este documento es para la ronda de preguntas: úsalo si el profesor
pregunta "¿y en producción, esto no daría falsos positivos?".

---

## 1. Falsos positivos reales, regla por regla

### Regla 1 — SSRF Autodiscover Bypass

| Fuente real de falso positivo | Por qué pasaría | Cómo se distingue de un ataque real |
|---|---|---|
| **Escaneos de vulnerabilidades autorizados** | Herramientas como Nessus, Qualys o Tenable, usadas por el propio equipo de seguridad de la organización para verificar si el servidor sigue expuesto a ProxyLogon, generan **exactamente el mismo patrón** de URI que un atacante real — es la prueba de concepto pública, cualquier scanner la reproduce. | Correlacionar contra una ventana de mantenimiento programada o un ticket de "vulnerability assessment" autorizado; la IP de origen sería la del propio equipo de seguridad, no una IP externa desconocida. |
| **Configuraciones híbridas de Exchange** | En un despliegue híbrido real (Exchange on-premise + Exchange Online/Office 365), el proceso legítimo de coexistencia **sí** genera tráfico de Autodiscover que referencia dominios externos (el tenant de Office 365) como parte del descubrimiento automático de buzones migrados a la nube. | El dominio externo en un entorno híbrido legítimo sería el tenant conocido de Office 365 de la propia organización, no un dominio arbitrario y desconocido como `update-cdn-svc.net`; además, el tráfico híbrido legítimo no trae las cookies `X-AnonResource-Backend`/`X-BEResource` falsificadas. |
| **Balanceadores de carga / proxies inversos mal configurados** | Si el balanceador reescribe URIs de forma no estándar, ocasionalmente puede introducir caracteres especiales en la query string que coincidan parcialmente con el patrón de la regla. | Estos casos generan el patrón de forma constante y predecible en el tiempo (no en ráfagas cortas como un ataque), y usualmente sin las cookies internas de Exchange. |

### Regla 2 — Webshell Drop

| Fuente real de falso positivo | Por qué pasaría | Cómo se distingue |
|---|---|---|
| **Actualizaciones legítimas de Exchange (Cumulative Updates)** | La instalación de un CU de Exchange reescribe archivos `.aspx` en las mismas carpetas que monitoreamos — es tráfico de escritura de archivo completamente legítimo. | Correlacionar con la ventana de mantenimiento de parcheo documentada; el proceso responsable sería `msiexec.exe` o el instalador de Exchange, no `w3wp.exe` respondiendo a una petición HTTP externa. |
| **Personalización de branding corporativo** | Algunos administradores despliegan páginas de login personalizadas (`.aspx`) en las carpetas de autenticación de OWA para agregar el logo/colores de la empresa. | Este cambio ocurre una sola vez, vía un despliegue interno (no vía una petición POST desde internet), y queda documentado en un ticket de cambio. |
| **Nuestra regla actual es literal, no genérica** | Tal como está configurada (`cs_uri_stem="/ecp/proxyLogon.ecp"` y `"/owa/auth/help.aspx"` exactos), en producción real **no generaría ningún falso positivo — pero tampoco detectaría un ataque real** si el atacante usa cualquier otro nombre de archivo o ruta distinta. | Ver sección 3 — esta es una limitación real de nuestra implementación de demo, no algo que "no pasaría". |

### Regla 3 — C2 vía Webshell (w3wp.exe → cmd.exe/powershell.exe)

| Fuente real de falso positivo | Por qué pasaría | Cómo se distingue |
|---|---|---|
| **Instaladores y parches de Exchange** | El propio instalador de Exchange, durante actualizaciones, puede invocar procesos auxiliares desde el contexto de IIS en ciertas configuraciones. | Ocurre exclusivamente durante ventanas de mantenimiento documentadas, con el servicio en modo de mantenimiento (no sirviendo tráfico de usuarios). |
| **Herramientas de monitoreo (SCOM y similares)** | System Center Operations Manager y agentes de monitoreo similares a veces despliegan "management packs" para Exchange que ejecutan scripts de diagnóstico periódicos, algunos de los cuales pueden invocarse desde procesos relacionados con IIS. | Estos procesos corren en un horario predecible y recurrente (cada X minutos, todos los días), no en ráfagas correlacionadas con tráfico HTTP anómalo previo. |
| **Software de backup/antivirus con integración a IIS** | Algunos agentes de backup o antivirus se integran a nivel de proceso con servicios de IIS para escaneo en tiempo real. | El proceso hijo generado sería el binario conocido del antivirus/backup (firmado, con ruta de instalación estándar), no `cmd.exe`/`powershell.exe` genéricos con parámetros de reconocimiento. |

### Regla 4 — Exportación de Buzón (`New-MailboxExportRequest`)

> **Esta es, con diferencia, la regla con mayor probabilidad de falso positivo en un entorno real.**

| Fuente real de falso positivo | Por qué pasaría | Cómo se distingue |
|---|---|---|
| **Migraciones de buzón legítimas** | Es el uso administrativo normal y documentado de este cmdlet — TI lo usa constantemente para migrar usuarios, hacer respaldos o cumplir con e-discovery legal. | El `-FilePath` de una exportación legítima apunta a un recurso de red interno controlado por TI (ej. `\\backup-server\exports\`), **nunca** a una carpeta dentro de la raíz web pública como `aspnet_client`. |
| **Cumplimiento legal / retención de datos (litigation hold)** | Los departamentos legales solicitan exportaciones de buzones específicos como parte de procesos de e-discovery. | Estas exportaciones están asociadas a un ticket de solicitud formal y a una cuenta de administrador nombrada (no a la cuenta `SYSTEM` ni ejecutada vía un webshell). |
| **Procesos de offboarding de empleados** | Al desvincularse un empleado, es común exportar su buzón antes de eliminar la cuenta. | Ocurre en horario laboral, correlacionado con un evento de baja en el sistema de RRHH/Directorio Activo. |

### Regla 5 — Acceso a LSASS

| Fuente real de falso positivo | Por qué pasaría | Cómo se distingue |
|---|---|---|
| **Soluciones EDR/antivirus legítimas** | Casi todo EDR moderno accede a LSASS como parte de su propio monitoreo de credenciales (para detectar *otros* ataques). Ya excluimos `MsMpEng.exe` en nuestra regla, pero en producción habría que mantener una lista blanca actualizada de todos los EDR desplegados. | El proceso fuente sería un binario firmado y conocido del EDR corporativo, con `GrantedAccess` típicamente de solo lectura limitada, no el acceso amplio que usa `procdump`. |
| **Depuración autorizada de Microsoft Support** | En casos de soporte técnico complejos, Microsoft puede indicar a un administrador ejecutar `procdump` legítimamente contra un proceso para diagnóstico — en casos raros, esto podría incluir LSASS bajo un caso de soporte específico. | Extremadamente infrecuente, siempre asociado a un número de caso de soporte de Microsoft documentado, ejecutado por una cuenta de administrador nombrada, no desde una carpeta temporal. |
| **Herramientas de gestión de contraseñas/identidad** | Algunas soluciones de IAM (Identity and Access Management) empresariales interactúan con APIs de bajo nivel relacionadas con autenticación. | Estas soluciones están registradas como software autorizado, con rutas de instalación estándar y certificados válidos. |

---

## 2. Qué SÍ dispararía como falso positivo con nuestra configuración actual (limitaciones honestas)

Nuestras reglas, tal como están escritas para esta demo, tienen puntos débiles reales que hay que
reconocer si preguntan:

- **La Regla 2 es literal, no genérica**: busca exactamente `help.aspx` y `proxyLogon.ecp`. En
  producción, cualquier variación del nombre del webshell la evadiría por completo. La versión
  "mejorada" que documentamos en `03_guia_splunk.md` (basada en los patrones oficiales de
  `Test-ProxyLogon.ps1` de Microsoft: `Set-*VirtualDirectory`, `Reset*VirtualDirectory#`) es más
  robusta porque busca el *comportamiento administrativo abusado*, no el nombre de archivo
  resultante.
- **La Regla 5 con lista de exclusión estática**: si mañana se despliega un nuevo EDR o herramienta
  de backup no incluida en el `NOT SourceProcessName IN (...)`, generaría ruido hasta que alguien la
  agregue a la lista — esto es exactamente el "tuning continuo" que menciona la teoría del curso
  como parte del ciclo de vida de un SIEM.
- **Ausencia de contexto de horario/negocio**: ninguna de nuestras 5 reglas distingue tráfico en
  horario laboral vs. fuera de horario. Una regla de producción madura añadiría ese contexto (ej.
  "exportación de buzón fuera de horario administrativo" como factor de mayor severidad, no como
  condición binaria).
- **Sin correlación con sistema de gestión de cambios (ITSM)**: en una organización madura, las
  alertas se cruzarían automáticamente contra el sistema de tickets de cambio (ServiceNow, Jira
  Service Management, etc.) para descartar automáticamente actividad ya autorizada — nosotros no
  simulamos esa integración por estar fuera del alcance elegido (SIEM, no SOAR).

---

## 3. Alcance y límites de nuestra solución SIEM — hasta dónde llega

**Lo que SÍ cubre:**
- Detección basada en reglas/firmas de comportamiento conocido (las 5 reglas + validación + prueba
  de FP), sobre 2 fuentes de log reales (red y host).
- Enriquecimiento con threat intelligence externa (VirusTotal, lookups de IOCs reales).
- Correlación temporal básica entre eventos de ambas fuentes.
- Visualización y triage guiado (dashboards, línea de tiempo).

**Lo que NO cubre (limitaciones reales, no ocultarlas):**
- **No hay una tercera fuente de red** (firewall/NetFlow) — no vemos el tráfico saliente hacia la
  infraestructura del atacante más allá de lo que registra IIS; un firewall aportaría visibilidad
  adicional de conexiones C2 fuera del canal HTTP.
- **No hay EDR real** — nuestra "Regla 5" simula lo que un EDR vería nativamente con mucha más
  fidelidad (comportamiento de memoria, cadenas de proceso completas, detección de inyección de
  código). Sin EDR, dependemos enteramente de lo que Windows Event Log decide registrar.
- **No hay UEBA (User and Entity Behavior Analytics)** — no construimos una línea base de
  comportamiento "normal" por usuario/servidor; todas nuestras reglas son estáticas (patrones
  fijos), no basadas en desviación estadística de comportamiento histórico.
- **No detecta variantes desconocidas del ataque** — si un atacante logra ejecutar código sin
  generar un proceso hijo visible (ej. inyección de código in-process, reflection de .NET), la
  Regla 3 no lo vería, porque depende específicamente de la creación de un nuevo proceso.
- **Depende de que el logging esté intacto** — si el atacante logra deshabilitar el registro de
  eventos o purgar el Event Log (una técnica de anti-forensics real y documentada), la evidencia
  simplemente no existiría para que Splunk la correlacione.
- **Es detección, no respuesta automatizada** — elegimos SIEM y no SOAR; ninguna de nuestras
  acciones de contención (bloqueo de IP, aislamiento de host) ocurre automáticamente, requieren
  intervención manual del analista.

**QUÉ DECIR si preguntan por esto:**
> *"Nuestra solución cubre bien la detección basada en comportamiento conocido sobre las fuentes que
> tenemos, pero somos conscientes de que no reemplaza una arquitectura de defensa en profundidad
> completa — en un entorno real, recomendaríamos sumar una tercera fuente de red, un EDR dedicado, y
> eventualmente evolucionar hacia detección basada en comportamiento (UEBA) para casos que nuestras
> reglas estáticas no cubrirían."*

---

## 4. Metodología general para discernir un ataque real de un falso positivo

Esto aplica más allá de ProxyLogon — es el proceso que un analista de SOC seguiría ante *cualquier*
alerta ambigua:

1. **Correlación multi-señal, nunca una sola alerta aislada**: nuestra "cadena forense" (Regla 1 →
   2 → 3 → 4/5) es exactamente esto — un solo evento aislado puede ser ruido, pero 3-4 fases del
   mismo Kill Chain ocurriendo en secuencia, sobre el mismo activo, en una ventana de minutos, deja
   de ser plausible como coincidencia.
2. **Contexto de identidad y autorización**: ¿la acción la ejecutó una cuenta de servicio conocida,
   un administrador nombrado, o un contexto anónimo/SYSTEM sin sesión de usuario asociada? Un
   `New-MailboxExportRequest` ejecutado por `jsalazar-admin` durante horario laboral es
   estructuralmente distinto a uno ejecutado por SYSTEM a través de un proceso `w3wp.exe`.
3. **Contexto de destino/ruta**: ¿el archivo resultante se guarda en un recurso interno controlado,
   o en una ruta accesible públicamente por web? Este solo factor distingue casi perfectamente una
   exportación administrativa legítima de una maliciosa en el caso de ProxyLogon.
4. **Correlación contra ventanas de cambio conocidas**: cruzar la alerta contra el calendario de
   mantenimiento/parcheo — si coincide con una ventana documentada y autorizada, baja
   significativamente la probabilidad de que sea malicioso.
5. **Enriquecimiento externo**: reputación de IP (VirusTotal/AbuseIPDB), si el hash de un archivo
   sospechoso aparece en bases de malware conocidas, si el patrón coincide con IOCs publicados de
   campañas activas.
6. **Prueba de negativo (lo que hace nuestra Regla 7)**: correr la misma lógica de detección contra
   una muestra conocida de actividad benigna — si dispara ahí también, la regla está mal calibrada,
   no el evento bajo investigación.
7. **Documentar y afinar (tuning)**: cada falso positivo confirmado se documenta, y la regla se
   ajusta (agregando una exclusión, un umbral, o un contexto adicional) — es un ciclo continuo, no
   una tarea de una sola vez. Esto es lo que la teoría del curso llama explícitamente "tuning
   continuo" como parte del ciclo de vida de gestión de un SIEM.
