# GUIÓN MAESTRO — Léelo de principio a fin, en orden, durante la presentación

Este es el único documento que necesitas abierto durante tu parte de la exposición. Cada sección
tiene: **QUÉ CLIC HACER** → **QUÉ DECIR** (en cursiva, cita casi textual) → **QUÉ SIGNIFICA** (para
que entiendas lo que estás leyendo, no solo lo repitas).

---

## ANTES DE EMPEZAR — checklist de 30 segundos

- [ ] Navegador abierto en `http://26.28.194.96:8000`
- [ ] Sesión iniciada con usuario `aabrisquetaz`
- [ ] Ten esta pestaña (este documento) abierta en una segunda ventana/monitor si puedes
- [ ] Recuerda: **cualquier búsqueda que hagas, el rango de tiempo (arriba a la derecha) debe estar
      en "Last 7 days" o "All time"** — si dice "Last 24 hours" no vas a ver nada y te vas a poner
      nervioso en vivo. Configúralo ANTES de empezar a compartir pantalla.

---

## PARTE 1 — Apertura (30 segundos, antes de tocar Splunk)

**QUÉ DECIR:**
> *"Voy a mostrar cómo implementamos la función Detect del NIST Cybersecurity Framework para el
> ataque ProxyLogon: recopilación, normalización, correlación y alertamiento sobre las fases del
> Cyber Kill Chain, usando Splunk como SIEM. Todo lo que van a ver está corriendo en vivo, no son
> capturas de pantalla."*

**QUÉ SIGNIFICA lo que acabas de decir**: estás anclando tu exposición a dos marcos teóricos vistos
en el curso — el NIST CSF (que tiene 5 funciones: Identify, Protect, Detect, Respond, Recover; tu
proyecto cubre Detect a fondo) y el Cyber Kill Chain (el modelo de 7 fases de Lockheed Martin que
describe cómo progresa un ataque).

---

## PARTE 2 — Navegar a Splunk (clic por clic)

1. En la pantalla principal de Splunk, busca en el listado de Apps **"Search & Reporting"** y haz
   clic para entrar. (Si ya estás dentro, sigue al paso 2.)
2. En el menú superior de esa app verás: `New Search | Search | Analytics | Datasets | Reports |
   Alerts | Dashboards | Modules`.

**QUÉ DECIR mientras navegas:**
> *"Estamos en el módulo Search & Reporting de Splunk, donde configuramos un índice llamado
> `proxylogon` que contiene dos fuentes de log reales de la organización simulada: logs de IIS
> (el servidor web de Exchange) y Windows Event Logs (el sistema operativo del servidor)."*

---

## PARTE 3 — Dashboard "Overview" (primero muestra la vista general)

**CLIC**: menú superior → **Dashboards** → clic en **"ProxyLogon - Overview"**.

**QUÉ DECIR, panel por panel, en orden de izquierda a derecha / arriba a abajo:**

### Panel 1: "Volumen de eventos por fuente"
> *"Este es el gráfico de picos de tráfico que pide la rúbrica del curso — una de las funciones
> nativas de un SIEM. Vemos las dos fuentes de log — IIS en un color, Windows Event Log en otro —
> a lo largo del incidente simulado."*

**QUÉ SIGNIFICA**: es un `timechart` de Splunk — agrupa los eventos en bloques de 30 minutos y
cuenta cuántos hay de cada `sourcetype`. Sirve para ver de un vistazo si hubo un pico anómalo de
actividad (útil para detectar, por ejemplo, un escaneo masivo).

### Paneles 2-4: los números grandes (Regla 1, Regla 3, Regla 4, Regla 5)
> *"Estos son contadores en vivo de 4 de nuestras 5 reglas de detección — cada número es el
> resultado de una búsqueda SPL corriendo contra los datos ahora mismo, no un valor fijo."*

### Panel: "Falsos Positivos Regla 1"
> *"Este panel en particular responde a una observación específica que nos hizo el profesor al
> aprobar la propuesta: que no olvidáramos confirmar que no es un falso positivo. El número que ven
> aquí es 0 — verde significa que está en el rango aceptable."*

### Panel: "Top IPs origen"
> *"Aquí vemos las IPs que más tráfico generan contra el servidor — permite identificar rápidamente
> cuál es la IP anómala entre el tráfico normal de los empleados."*

---

## PARTE 4 — Las 7 alertas (el corazón de tu exposición)

**CLIC**: menú superior → **Alerts**. Verás una lista de 7 filas.

**QUÉ DECIR antes de entrar a la primera:**
> *"Configuramos 7 búsquedas guardadas como alertas en Splunk. Las 5 primeras cubren cada fase del
> Kill Chain del ataque. La sexta valida nuestras reglas contra un dataset real y público de una
> ejecución genuina del exploit. La séptima es la prueba de falsos positivos que ya mencioné."*

Para cada alerta: haz clic en el **nombre** → busca el menú de tres puntos `...` o "Edit" → **"Open
in Search"** para verla corriendo en vivo con resultados.

---

### 🔴 ALERTA 1 — "01 - ProxyLogon SSRF Autodiscover Bypass"

**QUÉ DECIR (fase):**
> *"Esta regla detecta la fase de Explotación — la vulnerabilidad CVE-2021-26855, que le da nombre
> a todo el ataque: 'ProxyLogon'."*

**Señala el código SPL en pantalla y di:**
> *"La búsqueda filtra el tráfico de IIS hacia rutas de autodiscover o ecp, que además contengan
> una arroba en los parámetros, o las cookies internas de Exchange `X-AnonResource-Backend` — un
> patrón que jamás debería venir de un cliente externo. Y esta última línea usa el comando `lookup`
> de Splunk para cruzar automáticamente la IP de origen contra una tabla de 16 IPs reales de la
> campaña HAFNIUM, publicadas por Volexity, Microsoft y Huntress Labs."*

**Señala los resultados en pantalla (7 filas) y di:**
> *"Vemos 7 eventos, todos desde la IP 103.77.192.219, todos marcados `TRUE` en la columna
> `ip_conocida_hafnium` — esta IP no la inventamos, es un indicador de compromiso real, documentado
> en el advisory oficial de CISA, AA21-062A. Las primeras 6 filas son intentos de bypass SSRF cada
> 15-18 segundos — el atacante repite la petición porque no siempre funciona a la primera. El campo
> `time_taken` está en 8 milisegundos — demasiado rápido para un humano, es un script automatizado.
> La séptima fila, a las 09:46:05, ya es un POST al panel de administración — es la transición hacia
> la siguiente fase."*

**Si preguntan "¿por qué es SSRF?" responde:**
> *"SSRF significa Server-Side Request Forgery. El atacante manda una URL con `@dominio-externo`
> después de `autodiscover.json`. Exchange interpreta mal esa sintaxis y termina mandándose una
> petición a sí mismo, hacia su propio backend interno, creyendo que viene de un proceso de
> confianza. Así el atacante lee datos sin necesitar contraseña."*

---

### 🔴 ALERTA 2 — "02 - ProxyLogon Webshell Drop"

**QUÉ DECIR (fase):**
> *"Esta regla detecta la fase de Instalación — la vulnerabilidad CVE-2021-27065."*

**Código SPL:**
> *"Buscamos dos eventos exactos: el POST que escribe el archivo malicioso, y el GET que confirma
> que quedó accesible desde internet."*

**Resultados (2 filas):**
> *"Fila 1, a las 09:46:05: un POST a `/ecp/proxyLogon.ecp` — de aquí viene el nombre de toda la
> vulnerabilidad. Este endpoint permite, abusando de una función administrativa de Exchange llamada
> Set-OabVirtualDirectory, escribir un archivo arbitrario en el disco del servidor. Noten el
> `time_taken` de 340 milisegundos, mucho más lento que las peticiones anteriores — tiene sentido,
> el servidor está escribiendo un archivo nuevo. Fila 2, 15 segundos después: un GET a
> `/owa/auth/help.aspx`, respuesta 200 — el atacante confirma que su webshell ya está ahí y
> funciona. El nombre `help.aspx` no lo inventamos: es uno de 31 nombres de archivo documentados
> realmente en esta campaña, en un repositorio público que compiló el propio equipo de
> investigación de seguridad de Splunk."*

**Si preguntan "¿qué es un webshell?" responde:**
> *"Es un archivo, en este caso .aspx, que el atacante deja en el servidor web. Cuando alguien le
> manda una petición HTTP con un comando, el webshell lo ejecuta a nivel de sistema operativo y
> devuelve el resultado. Es básicamente una puerta trasera controlable por HTTP."*

---

### 🔴 ALERTA 3 — "03 - ProxyLogon C2 via Webshell (w3wp child process)"

**QUÉ DECIR (fase):**
> *"Esta regla detecta la fase de Comando y Control. Y es importante: esta es nuestra SEGUNDA
> fuente de log — ya no es tráfico de red de IIS, es Windows Event Log, evidencia a nivel de
> sistema operativo del servidor."*

**Código SPL:**
> *"Buscamos el EventCode 4688 de Windows — que significa 'se creó un nuevo proceso' — donde el
> proceso padre sea w3wp.exe, que es el proceso que ejecuta IIS y Exchange."*

**Resultados (4 filas):**
> *"Los cuatro comandos que el atacante ejecutó a través del webshell, en orden: a las 09:46:46,
> `whoami` — el comando más básico para saber con qué privilegios está corriendo. A las 09:47:41,
> `ipconfig /all` — reconocimiento de la red interna. A las 09:49:06, `net user` — enumera cuentas
> de usuario locales, buscando objetivos para moverse lateralmente. Y a las 09:51:01, PowerShell con
> el parámetro `-enc`, que ejecuta un comando codificado en Base64 — una técnica de evasión, porque
> el comando real no aparece en texto claro en el log."*

**El punto más importante de esta alerta:**
> *"w3wp.exe es el proceso que sirve páginas web. En operación normal, jamás debería generar una
> consola de comandos como proceso hijo. Cuando esto pasa, es la evidencia más inequívoca de que
> hay un webshell ejecutando comandos arbitrarios."*

---

### 🔴 ALERTA 4 — "04 - ProxyLogon Mailbox Export"

**QUÉ DECIR (fase):**
> *"Fase de Acciones sobre los objetivos — el atacante empieza a preparar el robo de información."*

**Código SPL:**
> *"El EventCode 4104 es el registro de bloques de script de PowerShell de Windows — Windows guarda
> el contenido completo del script ejecutado, no solo que se corrió PowerShell. Buscamos que ese
> contenido incluya el cmdlet New-MailboxExportRequest."*

**Resultado (1 fila):**
> *"A las 09:52:00: `New-MailboxExportRequest -Mailbox jgarcia -FilePath` hacia una carpeta dentro
> de la raíz web de IIS. Este es un cmdlet legítimo de Exchange, normalmente usado por
> administradores para exportar buzones a un archivo .pst para migraciones o respaldos. El
> atacante lo abusa: exporta el buzón completo de un empleado hacia una carpeta pública del
> servidor web — convierte un archivo interno en algo descargable por HTTP desde internet."*

**Por qué es sospechoso y no una operación normal de TI:**
> *"Una exportación de buzón administrativa real jamás se guarda dentro de la carpeta pública del
> servidor web — se guarda en un recurso de red interno controlado. Guardarlo ahí es la firma de
> alguien que necesita descargarlo después vía HTTP."*

---

### 🔴 ALERTA 5 — "05 - ProxyLogon LSASS Access"

**QUÉ DECIR (fase):**
> *"Sigue siendo Acciones sobre los objetivos — ahora, robo de credenciales."*

**Código SPL:**
> *"El EventCode 10 registra cuando un proceso abre acceso a la memoria de otro proceso. lsass.exe
> es el proceso de Windows que guarda en memoria las credenciales de los usuarios que iniciaron
> sesión — es el objetivo clásico para robo de contraseñas. Excluimos explícitamente procesos
> legítimos que normalmente acceden ahí, como el antivirus de Windows, para reducir falsos
> positivos."*

**Resultado (1 fila):**
> *"A las 09:53:30: procdump.exe accede a lsass.exe, con permisos de lectura de memoria. Procdump
> es una herramienta legítima de Microsoft Sysinternals, normalmente usada para diagnóstico — el
> atacante la abusa, una técnica que se llama 'living off the land': usar herramientas legítimas
> del propio sistema para actividad maliciosa. Además, está ubicada en C:\Windows\Temp, la carpeta
> temporal — no es donde vive normalmente una herramienta administrativa instalada, es típico de un
> binario subido por el atacante."*

**Mapeo MITRE ATT&CK (dilo, suena muy sólido):**
> *"Esta técnica está catalogada en el framework MITRE ATT&CK como T1003.001, Robo de Credenciales
> del Sistema Operativo desde la memoria de LSASS — una de las técnicas más buscadas en cualquier
> SOC real."*

---

### 🟢 ALERTA 6 — "06 - Validación con dataset real OTRF" (tu momento más fuerte, dale énfasis)

**QUÉ DECIR (introducción, cambia el tono aquí — esto es distinto a todo lo anterior):**
> *"Esta alerta es diferente a las cinco anteriores. No corre contra nuestra simulación — corre
> contra un dataset público y real, publicado por OTRF, Open Threat Research Forge, un equipo de
> investigación de amenazas reconocido en la comunidad de ciberseguridad. Son 28 eventos Sysmon
> capturados el 14 de marzo de 2021 al ejecutar el exploit público de ProxyLogon contra un servidor
> Exchange de laboratorio real."*

**Código SPL:**
> *"Buscamos el mismo patrón que en la Alerta 3 — un proceso creado con padre w3wp.exe — pero ahora
> sobre datos genuinos, no simulados."*

**Resultados (3 filas):**
> *"Y aquí está la validación: `cmd /c whoami`, generado por w3wp.exe, en el servidor real
> MXS01.azsentinel.local — exactamente el mismo patrón que representamos en nuestra Alerta 3."*

**La frase que cierra esta parte — apréndetela literal:**
> *"No nos quedamos con demostrar que la regla funciona contra nuestra simulación. La validamos
> contra evidencia real y pública de que el exploit se ejecutó de verdad. Esta es la diferencia
> entre una regla que se ve razonable en la teoría, y una regla que sabemos que detectaría el
> ataque real."*

---

### 🟢 ALERTA 7 — "07 - Prueba de Falsos Positivos"

**QUÉ DECIR:**
> *"Esta responde directamente a la observación que nos hizo el profesor al aprobar la propuesta:
> no olvidar confirmar que una alerta no es un falso positivo. Tomamos exactamente la misma lógica
> de la Alerta 1, pero la corrimos filtrando solo tráfico interno legítimo de la organización —
> las IPs de los empleados reales."*

**Resultado:**
> *"El resultado es 0. De todo el tráfico normal que generamos — logins a OWA, consultas de Outlook,
> sincronización de dispositivos móviles — ninguno coincide con el patrón de ataque. No es solo una
> afirmación de que 'la regla es precisa' — es evidencia cuantitativa."*

---

## PARTE 5 — Dashboard "Detalle por Fase" (el cierre visual)

**CLIC**: menú superior → **Dashboards** → **"ProxyLogon - Detalle por Fase"**.

**QUÉ DECIR, panel por panel (de arriba a abajo):**

1. **Fase 1 - Reconocimiento**: *"Antes del ataque real, tres IPs distintas escanean el servidor
   buscando el endpoint de autodiscover — todas reciben 403, rechazadas, es el sondeo previo."*
2. **Fase 2 - Explotación**: *"El bypass SSRF que ya vimos en la Alerta 1."*
3. **Fase 3 - Instalación**: *"La escritura y confirmación del webshell, Alerta 2."*
4. **Fase 4 - C2**: *"Los 4 comandos ejecutados, Alerta 3."*
5. **Fase 5a - Exportación de buzón** y **Fase 5b - LSASS**: *"Alertas 4 y 5."*
6. **Fase 5c - Exfiltración**: *"Este panel es nuevo — muestra la descarga final del archivo .pst
   por HTTP, a las 09:54:15, con un `time_taken` de 5200 milisegundos, una transferencia grande —
   es la última fase del kill chain, la exfiltración de datos."*
7. **Línea de tiempo completa**: *"Y este panel final junta las 9 etapas del ataque en una sola
   tabla cronológica: desde el primer escaneo a las 09:12, hasta la exfiltración a las 09:54 —
   42 minutos de principio a fin."*

**Frase de cierre de toda tu sección:**
> *"En resumen: implementamos el pipeline completo de un SIEM — recopilación de dos fuentes de log,
> normalización, correlación mediante 7 reglas, y alertamiento — sobre las fases reales del Cyber
> Kill Chain de ProxyLogon, con una regla de validación contra evidencia real del exploit, y una
> prueba cuantitativa de que el sistema no genera ruido con tráfico legítimo. Nuestra alerta
> inicial se hubiera disparado 9 minutos antes de que el atacante lograra exfiltrar cualquier dato
> — esa es la ventana real de contención que un SOC tendría con este sistema."*

---

## SI ALGO FALLA EN VIVO (plan B)

- Si una búsqueda no carga o da error de red: di *"mientras carga, les explico qué debería
  mostrar"* y sigue leyendo la sección correspondiente de este guión — ya sabes exactamente qué
  número/fila va a aparecer.
- Si Splunk está lento: recuerda que grabaron un video de respaldo — pueden ofrecer mostrarlo si el
  profesor lo permite.
- Si preguntan algo que no está aquí: revisa `docs/04_autoexamen.md` (20 preguntas con respuesta) y
  `docs/06_explicacion_profunda_eventos.md` (glosario completo de IOCs).
