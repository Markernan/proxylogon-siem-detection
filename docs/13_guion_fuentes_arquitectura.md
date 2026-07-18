# Guión Detallado — "Fuentes de Log + Arquitectura" (Bloque 5 de la exposición)

Versión extendida del Bloque 5 de `docs/08_linea_tiempo_exposicion_completa.md`. Este es el bloque
puente entre la parte de tu compañero (Kill Chain/artefactos) y la tuya (las 7 alertas) — tiene que
sonar sólido porque es donde el profesor evalúa explícitamente "mínimo 2 fuentes de logs" de la
rúbrica de los 15 puntos de SIEM.

---

## Apertura — por qué Splunk

> *"Para la detección elegimos Splunk Enterprise como solución SIEM. Es una de las plataformas más
> usadas en la industria para SOC reales, y el propio equipo de investigación de seguridad de
> Splunk publicó detecciones oficiales para este mismo ataque — lo cual nos permitió validar que
> nuestro enfoque está alineado con lo que un fabricante real recomienda, no solo con lo que a
> nosotros nos pareció razonable."*

---

## La arquitectura general

> *"Configuramos un único índice en Splunk llamado `proxylogon`, donde conviven las fuentes de log
> del incidente. Actualmente contiene 356 eventos en total: 296 de IIS, 32 de Windows Event Log —
> nuestras dos fuentes requeridas por la rúbrica — más 28 eventos adicionales de un tercer dataset
> que no es sintético sino real, que vamos a explicar más adelante en la Regla 6."*

**Cómo se cargaron los datos (si preguntan por el mecanismo técnico):**
> *"Los datos se cargaron vía el comando `oneshot` de la API REST de Splunk — apropiado para
> datasets históricos de una sola carga, a diferencia de un forwarder que sería para ingesta
> continua en producción. Cada fuente tiene su propio `sourcetype`, que es como Splunk clasifica y
> aplica reglas de extracción de campos distintas a cada tipo de log."*

---

## Fuente 1 — Logs de IIS (tráfico de red/perímetro)

> *"Nuestra primera fuente es el servidor web IIS de Exchange — la capa de red, lo que ve cualquier
> petición HTTP que llega al servidor desde internet. La usamos en formato **W3C Extended Log
> Format**, que es el formato nativo real que IIS produce — no lo normalizamos a JSON genérico
> deliberadamente, porque Splunk lo reconoce automáticamente con el sourcetype nativo `iis`, sin
> necesitar configuración adicional, y porque así es exactamente como un analista de SOC real vería
> estos datos en producción."*

**Campos clave de esta fuente (si preguntan qué información contiene):**
> *"Cada línea trae: fecha y hora, IP del servidor, método HTTP, la ruta solicitada (`cs_uri_stem`),
> los parámetros de la URL (`cs_uri_query`), la IP del cliente (`c_ip`), el user-agent, el código de
> respuesta HTTP (`sc_status`), y el tiempo de respuesta en milisegundos (`time_taken`). Estos
> últimos dos campos resultaron ser clave para la detección — el código 241 y los tiempos de
> respuesta anómalamente cortos son parte de cómo identificamos el patrón de ataque."*

**296 eventos — qué contienen:**
> *"De esos 296 eventos, la gran mayoría —alrededor de 280— son tráfico completamente benigno:
> empleados reales de CFP iniciando sesión en OWA, sincronizando Outlook, usando ActiveSync desde
> sus celulares. Los eventos del ataque están mezclados dentro de ese tráfico normal, deliberadamente
> — no aislamos el ataque en una tabla ya filtrada, porque eso no sería un ejercicio real de triage.
> Un analista de SOC nunca recibe los datos ya separados; tiene que encontrar la aguja en el
> pajar."*

---

## Fuente 2 — Windows Event Log (host/sistema operativo)

> *"Nuestra segunda fuente es el sistema operativo Windows del propio servidor Exchange — la capa de
> host, lo que ve el sistema operativo una vez que una petición ya llegó y potencialmente logró
> ejecutar algo. La representamos en formato `clave=valor`, tal como se ven los eventos de Windows
> cuando Splunk los indexa a través de su Add-on oficial para Windows — Splunk extrae estos pares
> automáticamente sin necesitar tocar ningún archivo de configuración adicional."*

**Los 3 EventCodes específicos que usamos (esto es importante, dilo con precisión):**
> *"Usamos 3 identificadores de evento distintos de Windows, cada uno capturando un tipo de
> actividad diferente: **EventCode 4688**, el identificador nativo de Windows Security Log para
> creación de procesos — es el que nos permite ver `w3wp.exe` generando `cmd.exe` o `powershell.exe`.
> **EventCode 4104**, el PowerShell Script Block Log — Windows guarda el contenido completo de
> cualquier script de PowerShell ejecutado, no solo el hecho de que se ejecutó. Y **EventCode 10**,
> en la convención de Sysmon para 'acceso a proceso' — el que usamos para detectar el acceso a la
> memoria de `lsass.exe`."*

**32 eventos — qué contienen:**
> *"De los 32 eventos de esta fuente, 25 son procesos completamente normales del sistema operativo
> —`svchost.exe`, `wmiprvse.exe`, procesos de background de Windows— y los 7 restantes son la
> evidencia directa del ataque: los 4 comandos ejecutados vía el webshell, la exportación del buzón,
> y el acceso a LSASS."*

---

## Por qué estas 2 fuentes específicamente (el argumento de diseño)

> *"No elegimos estas dos fuentes al azar. Como explicó [compañero], todo el ataque transcurre a
> través de un único punto de entrada — el servidor Exchange — sin necesitar moverse lateralmente
> hacia otros sistemas de la red de CFP. Eso significa que estas dos fuentes, ambas del mismo
> servidor, son estructuralmente suficientes para cubrir la detección de las 7 fases completas del
> Kill Chain: la fuente de red ve la explotación llegando desde afuera, y la fuente de host confirma
> que esa explotación efectivamente resultó en ejecución de código, no solo en un intento fallido.
> Es exactamente la combinación de evidencia perimetral y evidencia de endpoint que recomienda
> cualquier metodología de detección."*

---

## Bonus: la tercera fuente, y por qué no cuenta como "la fuente 3 de la rúbrica"

> *"Además de esas dos, tenemos un tercer sourcetype llamado `json_otrf_real`, con 28 eventos —
> pero es importante ser precisos: esta no es una tercera fuente del incidente de CFP, es un dataset
> **externo e independiente**, publicado por el equipo de investigación OTRF (Open Threat Research
> Forge), con eventos Sysmon reales capturados al ejecutar el exploit público de ProxyLogon en un
> laboratorio real en 2021. La usamos exclusivamente para la Regla 6, como validación cruzada — no
> la contamos como parte del requisito de '2 fuentes de log' de la rúbrica, porque no pertenece al
> incidente simulado de CFP. La mencionamos aparte para que quede claro que no estamos inflando el
> número de fuentes artificialmente."*

---

## Enriquecimiento integrado en la arquitectura (adelanto antes de las alertas)

> *"Una última pieza de la arquitectura antes de entrar a las alertas: cargamos 3 tablas de
> referencia —lo que Splunk llama *lookups*— con indicadores de compromiso reales de esta campaña:
> 16 IPs, 31 nombres de webshell, y varios user-agents usados por HAFNIUM para camuflarse, todos
> publicados por el equipo de investigación de seguridad de Splunk a partir de reportes de Volexity,
> Microsoft y Huntress Labs. Esto nos permite que Splunk cruce automáticamente nuestros eventos
> contra amenazas conocidas reales, en vez de depender únicamente de patrones de texto — lo van a
> ver en acción en la primera alerta."*

---

## Frase de cierre — transición hacia las alertas

> *"Con el índice, las dos fuentes, y el enriquecimiento ya configurados, vamos a mostrar ahora las
> 7 alertas que construimos sobre esta arquitectura, cada una correspondiente a una fase específica
> del Kill Chain que ya vimos."*

---

## Preguntas de profundización — prepárate para esto

- **¿Por qué no usaron un forwarder de Splunk en vez de `oneshot`?** → *"`oneshot` es apropiado para
  cargas históricas de una sola vez, como esta simulación. Un Universal Forwarder sería la elección
  correcta en producción, para ingesta continua en tiempo real desde el propio servidor."*
- **¿Por qué formato nativo y no JSON normalizado?** → *"Menor riesgo de que el parsing falle en un
  momento crítico, y es literalmente el formato que un SOC real vería — normalizar todo a JSON
  hubiera sido más parecido a un pipeline tipo Elasticsearch, que no es lo que elegimos."*
- **¿Cuántos eventos tiene cada sourcetype exactamente?** → `iis`: 296 · `windows_events_proxylogon`:
  32 · `json_otrf_real`: 28 (este último no cuenta para el requisito de 2 fuentes).
- **¿Qué pasaría si solo tuvieran 1 fuente?** → *"No podríamos confirmar que la explotación
  perimetral (fase de red) efectivamente resultó en compromiso del host — solo veríamos la mitad de
  la historia. Es exactamente el argumento que usamos para justificar por qué elegimos 2 fuentes
  correlacionadas, no una fuente con más volumen de datos."*
