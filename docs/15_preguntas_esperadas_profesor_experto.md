# Preguntas Esperadas del Profesor — Lista Maestra de Preparación

Organizado por categoría, pensado para un evaluador que conoce el tema a fondo (ya vimos, por el
foro del curso, que hace preguntas quirúrgicas y específicas a cada grupo). Cada pregunta tiene una
respuesta lista; donde la respuesta completa vive en otro documento, te lo indico para que la
repasen ahí. **Al final hay una sección de puntos débiles reales — no los escondan, antici­pen la
pregunta.**

---

## A. Sobre la elección del ataque y la metodología general

**1. ¿Por qué eligieron ProxyLogon y no otro ataque?**
→ Es real, documentado por fuentes primarias verificables (Microsoft, Volexity, CISA), con IOCs
públicos reutilizables, y el sector financiero está confirmado como efectivamente afectado según
ESET — no es una combinación forzada.

**2. ¿Por qué simularon el ataque en vez de replicarlo contra un Exchange real?**
→ Costo/beneficio: instalar Exchange real requiere Domain Controller adicional, ~20GB+ RAM, alto
riesgo de fallar en el primer intento, y los instaladores actuales ya vienen parchados —no se puede
reproducir el exploit real de todas formas. Compensamos anclando cada patrón a IOCs reales y
validando contra un dataset real de ejecución (Regla 6). Detalle completo: `docs/09`.

**3. ¿Cómo garantizan que sus datos sintéticos son representativos de un ataque real?**
→ Cada campo (webshell `help.aspx`, IP `103.77.192.219`, user-agent `DuckDuckBot`) viene de IOCs
públicos reales, no inventados — y lo validamos empíricamente contra el dataset real de OTRF
(Regla 6), donde el mismo patrón de detección coincidió.

**4. Su propuesta original mencionaba una organización financiera — ¿por qué ese sector
específicamente?**
→ Confirmado como efectivamente comprometido en la campaña real (reporte ESET, 10 grupos APT
distintos). Detalle: `docs/01`, sección 0.

---

## B. Sobre el Kill Chain y los CVEs

**5. ¿Cuál es la diferencia técnica entre CVE-2021-26858 y CVE-2021-27065, si ambas son "escritura
arbitraria de archivos"?**
→ Usan mecanismos distintos de Exchange para lograr el mismo resultado — 26858 vía el proceso de
Information Store, 27065 vía ECP (`Set-OabVirtualDirectory`), documentada como la vía más usada en
la explotación masiva real. Usamos 27065 en nuestra simulación por ser la documentada como
predominante.

**6. ¿Por qué no tienen una regla de detección para CVE-2021-26857 (deserialización en Unified
Messaging)?**
→ **Respuesta honesta**: nuestra cadena de explotación simulada usa la ruta CVE-2021-26855 →
CVE-2021-27065, que es la vía documentada como predominante en la explotación masiva real —
CVE-2021-26857 es una vía *alternativa* de ejecución de código, no estrictamente necesaria para el
éxito del ataque, y no la instrumentamos porque no forma parte de la cadena que elegimos simular.
Es una limitación de alcance consciente, no un olvido.

**7. ¿El ataque real siempre explota las 4 vulnerabilidades, o basta con menos?**
→ No, la combinación mínima documentada como suficiente es CVE-2021-26855 (acceso) +
CVE-2021-27065 (instalación) — la que simulamos.

**8. Explique el mecanismo SSRF con más profundidad — ¿qué sabe el atacante de antemano?**
→ Necesita conocer la estructura interna de nombres de backend de Exchange (típicamente
predecible/enumerable) para construir la cookie `X-AnonResource-Backend`; el resto del payload es
público desde la divulgación de Microsoft. Detalle completo: `docs/09`, Fase 4.

---

## C. Sobre la arquitectura de Splunk y decisiones técnicas

**9. ¿Por qué Splunk y no ELK/QRadar/Microsoft Sentinel?**
→ Splunk publicó su propia investigación de detección para este ataque exacto, lo que nos permitió
validar que nuestro enfoque está alineado con lo que el propio fabricante recomienda. Es además una
de las plataformas más usadas en SOCs reales.

**10. ¿Por qué usaron `oneshot` para cargar los datos en vez de un forwarder?**
→ `oneshot` es apropiado para cargas históricas de una sola vez, como esta simulación. Un Universal
Forwarder sería la elección correcta en producción, para ingesta continua en tiempo real.

**11. ¿Por qué eligieron el formato W3C nativo para IIS en vez de normalizar todo a JSON?**
→ Menor riesgo de parsing roto, más auténtico, y es literalmente el formato que un SOC real vería.
Detalle: `docs/00`, Decisión de diseño 2.

**12. ¿Cómo garantizan la integridad de los logs — que no fueron alterados después de generados?**
→ **Respuesta honesta**: en nuestra simulación no implementamos verificación de integridad (hashing,
WORM storage) — es una práctica real que documentamos como recomendación para producción
(`docs/02`, sección de Preparación) pero no la instrumentamos en la demo.

**13. ¿Qué es un `lookup` en Splunk, técnicamente, y cómo lo diferencian de un `join`?**
→ Un lookup carga una tabla externa completa a memoria/disco y la cruza campo-a-campo contra los
resultados de la búsqueda — más eficiente que un `join` para tablas de referencia relativamente
pequeñas y estáticas como nuestra lista de 16 IPs. Un `join` es más costoso computacionalmente y
pensado para correlacionar dos búsquedas dinámicas, no una búsqueda contra una tabla fija.

---

## D. Sobre las 7 reglas específicas (repaso rápido — detalle en `docs/06` y `docs/07`)

**14. Para cada regla: ¿por qué ese patrón y no otro? ¿Cómo reduce falsos positivos?**
→ Ver `docs/11` completo — tiene esto respondido regla por regla con causas reales de FP y cómo se
distinguen.

**15. ¿Por qué el código de respuesta `sc_status=241` en la Regla 1? ¿Es un código real
documentado?**
→ **Respuesta honesta, dilo así si preguntan directo**: usamos `241` como representación de un
código de respuesta no estándar, consistente con el comportamiento documentado de que Exchange
genera respuestas anómalas (fuera del rango HTTP estándar 200/403) cuando el proxy interno reenvía
exitosamente al backend. El valor específico `241` lo fijamos para el dataset sintético con el fin
de que sea visualmente distinguible de tráfico normal — no es un valor que verificamos letra por
letra contra una captura de log real de la campaña 2021, es nuestra representación razonada del
fenómeno documentado.

**16. La Regla 2 originalmente iba a usar `transaction` — ¿por qué no la usan al final?**
→ Se simplificó a rutas específicas por comportamiento menos predecible con los datos tras varias
iteraciones de carga durante el desarrollo — decisión de ingeniería documentada en `docs/03`.

**17. ¿Qué pasaría si el atacante usa un nombre de webshell distinto a `help.aspx`?**
→ La Regla 2, tal como está en la demo, es literal (busca ese nombre exacto) — **limitación
reconocida**, ver pregunta 24. La Regla 3 (comportamiento `w3wp.exe → shell`) sí seguiría
detectando, sin importar el nombre del archivo.

---

## E. Sobre el dataset real de OTRF (Regla 6)

**18. ¿Qué es OTRF y por qué confían en esa fuente?**
→ Open Threat Research Forge, equipo de investigación de amenazas reconocido en la comunidad de
ciberseguridad (creadores también del proyecto Mordor/HELK de datasets de seguridad). El dataset
está publicado en su plataforma pública `securitydatasets.com`.

**19. ¿Cómo obtuvieron y verificaron ese dataset?**
→ Se descargó directamente del repositorio público de OTRF en GitHub, se filtró a los eventos
relevantes (creación de procesos, acceso a LSASS, creación de archivos), y se corrigió un bug de
extracción de timestamp que inicialmente tomaba la fecha de carga en vez de la fecha real del
evento — corregido con una configuración de `props.conf` dedicada. Ver `docs/00`, sección de
incidentes resueltos.

**20. ¿Ese dataset prueba que el ataque específico contra CFP ocurrió, o solo que el patrón de
detección es válido?**
→ Solo lo segundo — es una validación de que el *patrón de detección* (w3wp.exe generando shell)
funcionaría contra una ejecución real del exploit, no evidencia de que CFP específicamente fue
atacada de esta forma exacta (CFP es hipotética).

---

## F. Sobre falsos positivos y límites de la solución (repaso — detalle completo en `docs/11`)

**21. ¿Esto no generaría falsos positivos en producción real?**
→ Sí, varias reglas los generarían — ver tabla completa en `docs/11`. La más propensa: Regla 4
(exportación de buzón), porque es una operación administrativa legítima y común. Se distingue por
el `-FilePath` de destino (interno vs. web-accesible) y por la identidad de quien la ejecuta.

**22. ¿Qué NO cubre su solución?**
→ Tercera fuente de red (firewall/NetFlow), EDR real, UEBA, variantes desconocidas del ataque,
respuesta automatizada. Ver `docs/11`, sección 3, respuesta completa lista para leer.

---

## G. Sobre el plan de triage y las métricas de tiempo

**23. ¿Cómo calcularon los tiempos de "trabajo del analista" (los 13.5 minutos)?**
→ **Respuesta honesta**: son estimaciones razonadas basadas en la complejidad de cada paso de
investigación (consulta a VirusTotal, análisis de campos, pivote entre fuentes), no una medición
cronometrada de una persona real ejecutando el triage — es una simulación pedagógica del proceso,
consistente con tiempos típicos reportados en literatura de operación de SOC, pero no un dato
empírico nuestro.

**24. ¿Es realista que un analista Nivel 1 complete todo esto solo, sin apoyo?**
→ En la práctica, ante un incidente de esta severidad, escalaría a Nivel 2 mucho antes de completar
todo el triage por su cuenta — nuestro flujo lo simplifica para fines de demostración; el
escalamiento real ocurriría tan pronto se confirma el patrón de cadena (después del Hallazgo 2).

---

## H. Sobre la organización CFP y el contexto regulatorio

**25. ¿Qué pasa si CFP no puede parchear de inmediato por restricciones operativas?**
→ Exchange On-Premises Mitigation Tool (EOMT) de Microsoft — mitigación de emergencia sin downtime
completo del servicio.

**26. ¿Cuál es el plazo legal real para notificar a la SBS o a la Autoridad de Protección de
Datos?**
→ **Respuesta honesta**: no profundizamos en el plazo exacto en días — mencionamos la obligación de
notificar conforme a la normativa vigente, sin citar un artículo específico con plazo numérico. Si
preguntan el plazo exacto, es válido responder: "no investigamos el plazo específico en días, pero
identificamos correctamente la obligación y a qué entidades correspondería notificar."

**27. ¿Por qué el sector financiero necesitaría mayor SLA de parcheo que otros sectores?**
→ Por la naturaleza crítica de los datos (financieros y personales) y por estar bajo supervisión
regulatoria directa de la SBS, con mayor exposición a sanciones y daño reputacional.

---

## I. Sobre el plan de respuesta al incidente

**28. Diferencia entre Playbook y Runbook — ¿cuál tienen ustedes?**
→ Ninguno formalmente automatizado — elegimos SIEM, no SOAR. Nuestro plan de respuesta
(`docs/02`) es más cercano a un Runbook manual (pasos técnicos concretos) que a un Playbook
orquestado. Lo decimos explícitamente si preguntan.

**29. ¿Por qué NIST y no SANS PICERL, o viceversa?**
→ Son prácticamente equivalentes en fases (Preparación, Detección/Análisis, Contención,
Erradicación, Recuperación, Lecciones Aprendidas/Post-Incidente) — elegimos NIST SP 800-61 por ser
la referencia más citada internacionalmente, mencionando SANS como marco alternativo equivalente.

---

## J. Preguntas comparativas / meta

**30. ¿Qué harían distinto con más tiempo y recursos?**
→ Agregar una tercera fuente (firewall/EDR real), implementar detección basada en comportamiento
(UEBA), y automatizar la respuesta con SOAR — todo documentado en `docs/11` como líneas de mejora
reales, no inventadas para la pregunta.

**31. ¿Este ataque sigue siendo relevante hoy (2026), años después del parche?**
→ Técnicamente no —el parche de marzo 2021 lo corrige—, pero servidores Exchange sin actualizar
siguen apareciendo en escaneos de internet años después (patrón documentado con muchas
vulnerabilidades críticas no parcheadas). Nuestra simulación asume precisamente eso: un servidor de
CFP que no aplicó el parche a tiempo — es la causa raíz que identificamos en el análisis.

---

## K. Puntos débiles reales — anticípense antes de que los pregunten

No los escondan si surgen — mejor mencionarlos con seguridad que parecer sorprendidos:

1. **No hay regla para CVE-2021-26857** (pregunta 6) — vía alternativa no instrumentada, decisión de
   alcance.
2. **La Regla 2 es literal, no genérica** (pregunta 17) — detecta el nombre exacto del webshell, no
   el comportamiento; la Regla 3 sí es genérica.
3. **Los tiempos de triage son estimados, no cronometrados** (pregunta 23) — simulación pedagógica.
4. **El código `sc_status=241`** (pregunta 15) — representación razonada, no verificada letra por
   letra contra un log real capturado.
5. **Sin verificación de integridad de logs** (pregunta 12) — documentado como recomendación, no
   implementado.
6. **Sin tercera fuente, sin EDR, sin UEBA** (pregunta 22) — alcance limitado a 2 fuentes por
   decisión de proyecto, no por desconocimiento de que existen mejores prácticas.

**Frase general para cualquiera de estos puntos débiles, si los presionan:**
> *"Es una limitación real de alcance para un proyecto de 2 personas en el tiempo disponible — lo
> identificamos nosotros mismos al documentar los límites de la solución, no es algo que se nos
> escapó sin darnos cuenta."*
