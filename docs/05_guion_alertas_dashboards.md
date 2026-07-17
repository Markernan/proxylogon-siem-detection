# Guión — Sección "Alertas y Detalle por Fase" (tu parte de la presentación)

Este documento conecta cada cosa que vas a mostrar en Splunk con la teoría exacta del curso
(`todo_elcurso.md`). El objetivo: que cuando muestres una alerta, no digas solo "esto detecta X",
sino que lo enmarques con el vocabulario y los conceptos que el profesor ya enseñó — así se nota que
entendiste la teoría y no solo construiste algo que funciona.

---

## 0. Frase de apertura (conecta tu sección con el marco general)

> "Vamos a mostrar cómo Splunk implementa la función **Detect** del NIST Cybersecurity Framework:
> recopilación, normalización, correlación y alertamiento de las 5 fases del kill chain de
> ProxyLogon, más un ejercicio de triage siguiendo el proceso de tratamiento de alertas visto en
> clase."

Esto ancla tu presentación a 2 marcos que el profesor mencionó explícitamente en la teoría:
**NIST CSF** (función Detect) y el **pipeline de un SIEM** (recopilación → agregación → parsing →
normalización → enriquecimiento → almacenamiento → correlación → alerta).

---

## 1. Al mostrar el Dashboard "Overview"

**Qué mostrar**: el gráfico de línea (picos de tráfico) y los números de cada regla.

**Qué decir, conectado a la teoría**:
- El gráfico de línea es literalmente lo que el enunciado del proyecto pide como "gráfico de picos
  de tráfico" — y es una de las **funcionalidades adicionales de un SIEM** vistas en el curso junto
  con "Dashboards y Reportes: Visualización de postura de seguridad, tendencias de amenazas".
- Menciona el **pipeline de datos**: "estos logs pasaron por Recopilación (oneshot desde los
  archivos), Parsing (Splunk interpreta el formato W3C de IIS y el texto de Windows Event Logs),
  Normalización (extracción de campos estándar como `c_ip`, `cs_uri_stem`, `EventCode`), y ahora
  Correlación (las 5 reglas)."

---

## 2. Al mostrar cada Regla (01 a 05) — el corazón de tu exposición

Para cada regla, sigue esta estructura de 3 frases (fase → método de alerta → por qué no es ruido):

### Regla 1 — SSRF Autodiscover Bypass
- **Fase**: Explotación (CVE-2021-26855).
- **Método de alerta**: el curso distingue 4 métodos de creación de alertas — la nuestra es una
  **"regla estática"** (patrón conocido: `@dominio-externo` en la URI), pero **mejorada con
  `lookup`** contra una tabla de IOCs reales, acercándose a lo que el curso llama **"análisis
  basado en riesgo"** (enriquecer con más contexto para confirmar, no solo un valor fijo).
- **Por qué no es ruido**: cita el dato real — 7 eventos, todos con `ip_conocida_hafnium=TRUE`.

### Regla 2 — Webshell Drop
- **Fase**: Instalación (CVE-2021-27065).
- Conecta con el concepto de **"Correlación Avanzada"**: no es un solo evento sospechoso, es la
  relación entre dos eventos (POST que escribe + GET que confirma) — "aplicar lógica que abarca
  múltiples eventos y tiempo", tal cual lo define la teoría del curso sobre SIEM.

### Regla 3 — C2 via Webshell
- **Fase**: Comando y Control.
- Este es el ejemplo más claro de **artefacto de host** (Windows Event Log) versus el
  **artefacto de red** (IIS) de las reglas 1 y 2 — usa esto para reforzar por qué el proyecto
  necesitaba **2 fuentes de log distintas**, no una sola: la red ve la petición, el host ve la
  ejecución del proceso.

### Regla 4 — Mailbox Export
- **Fase**: Acciones sobre los objetivos.
- Conecta con **UEBA (User and Entity Behavior Analytics)** mencionado en la teoría: exportar un
  buzón completo es una desviación del comportamiento "normal" de una cuenta de servicio — aunque
  no implementamos ML, el concepto de "esto es anómalo respecto a la línea base" es el mismo.

### Regla 5 — LSASS Access
- **Fase**: Acciones sobre los objetivos (robo de credenciales).
- Menciona explícitamente el **MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)** —
  el curso dedicó una sección completa a MITRE ATT&CK como "base de conocimiento de tácticas y
  técnicas", esto es la aplicación directa.

---

## 3. Al mostrar la Regla 6 (validación con dataset real de OTRF)

Este es tu **momento más fuerte** — enfatízalo. Conecta con la idea del curso de que "las
detecciones deben validarse, no solo diseñarse en la teoría":

> "No nos quedamos con demostrar que la regla funciona contra nuestra simulación. La corrimos
> también contra un dataset publicado por OTRF (Open Threat Research Forge), con eventos Sysmon
> reales capturados al ejecutar el exploit público de ProxyLogon contra un Exchange de laboratorio
> en 2021. El mismo patrón — `w3wp.exe` generando `cmd.exe` con `whoami` — aparece igual. Esto es
> la diferencia entre una regla que 'se ve razonable' y una regla **validada contra evidencia real**."

---

## 4. Al mostrar la Regla 7 (prueba de falsos positivos)

Esto responde **directamente** a la observación que el profesor le hizo a su grupo en la
aprobación de la propuesta: *"no olvidar considerar los pasos a seguir para triage de la alerta y
confirmar que no es un Falso Positivo."*

- Conecta con la teoría: el curso enseña que la **Categorización inicial** de una alerta puede ser
  Falso Positivo, Verdadero Positivo, o Indeterminado — y que "gran parte de las alertas vistas en
  el SOC suelen ser actividades genuinas y no maliciosas" (la famosa "fatiga de alertas").
- Muestra el dato: al filtrar la misma regla contra tráfico interno benigno (`192.168.1.*`), el
  resultado es **0**. Esto es evidencia cuantitativa de tuning, no solo una afirmación.

---

## 5. Al mostrar el Dashboard "Detalle por Fase" y la línea de tiempo completa

Aquí es donde cierras el círculo del **Cyber Kill Chain** completo (las 7 fases que el curso enseña:
Reconocimiento, Preparación/Weaponización, Distribución/Entrega, Explotación, Instalación, Comando y
Control, Acciones sobre los objetivos):

- Fase 1 (Reconocimiento): escaneo externo — corresponde a "el atacante recopila información sobre
  el objetivo" de la teoría.
- Fases 2 a 5c: el resto del kill chain, ya cubierto por las reglas.
- La tabla de "línea de tiempo completa" muestra las **9 etapas en orden cronológico** — usa esto
  para decir: *"esto demuestra que el proceso no es lineal solamente en la teoría — se ve en los
  timestamps reales, de las 09:12 a las 09:54, 42 minutos de principio a fin."*

---

## 6. Si te preguntan por el proceso de triage (Nivel 1 del SOC)

El curso define explícitamente los roles del SOC por niveles. Tú actuaste como **Analista de
Alertas Nivel 1**:

> "Nivel 1 se encarga del monitoreo continuo de alertas del SIEM, realiza el triaje inicial para
> descartar falsos positivos, y escala incidentes confirmados al siguiente nivel."

Y seguiste el proceso de **tratamiento de alertas** de la teoría, en el mismo orden:
**Evaluación inicial → Triage → Recopilación de información adicional (VirusTotal) →
Categorización → Prioridad final → Escalamiento a Nivel 2.**

Esto está en `docs/02_plan_triage_respuesta.md` — repásalo antes del sábado, palabra por palabra si
puedes, porque es prácticamente una copia aplicada de la sección "Tratamiento de alertas" del
sílabo.

---

## 7. Qué te falta reforzar (honesto, para que lo repases)

1. **Los 4 métodos de creación de alertas** (directas, reglas estáticas, análisis basado en riesgo,
   ML) — sé capaz de decir en qué categoría cae cada una de tus 7 reglas sin dudar.
2. **Las 5 funciones del NIST CSF** (Identify, Protect, Detect, Respond, Recover) — tu proyecto
   cubre Detect a fondo y Respond en el plan de respuesta; ten clara la frase de dónde encaja cada
   parte del proyecto si te preguntan "¿esto en qué función del NIST CSF cae?".
3. **Los factores de priorización** de la teoría (Severidad, Criticidad, Tipo de amenaza, Impacto
   potencial, Fiabilidad de la detección, Número de ocurrencias) — practica aplicar 2-3 de estos
   explícitamente a la Regla 1 en vivo si te preguntan "¿cómo priorizaron esta alerta?".
4. **Diferencia entre Playbook y Runbook** (visto en la sección SOAR de la teoría, aunque ustedes no
   implementaron SOAR) — por si preguntan por qué no lo hicieron: tienen la respuesta ya armada en
   `docs/00_PLAN_MAESTRO.md` (escogieron SIEM porque la rúbrica permite elegir uno).

---

## 8. Frase de cierre de tu sección

> "En resumen: aplicamos el pipeline completo de un SIEM — desde la recopilación de 2 fuentes de log
> hasta la correlación y el alertamiento — sobre las 7 fases reales del Cyber Kill Chain de
> ProxyLogon, con un proceso de triage que sigue exactamente la metodología vista en clase, y
> validamos que nuestras reglas detectarían no solo nuestra simulación sino la ejecución real y
> documentada del exploit."
