# Línea de Tiempo y Guión Completo — Exposición de 15 Minutos

Este documento arma la exposición completa (ambos integrantes) contra la rúbrica exacta del curso.
Cubre: quién dice qué, en qué minuto, y dónde se conectan las dos partes para que la transición se
sienta como un solo relato, no dos presentaciones pegadas.

## Cómo está repartida la nota (recuérdenlo al planificar tiempos)
- **Análisis técnico y lógico (5 pts)**: Kill Chain, operación detallada, artefactos, equipos +
  plan de respuesta → **parte de tu compañero**.
- **Detección SIEM (15 pts)**: mecanismos de detección, 2 fuentes de log, plan de triage con
  enriquecimiento (VirusTotal) y features nativas del SIEM → **se reparte entre los dos**.
- **Factores blandos** (sin puntaje directo pero definen la nota final): dominio individual,
  conocimiento de la implementación, capacidad de responder preguntas — **ambos deben poder cubrir
  la parte del otro si el profesor pregunta cruzado**.

---

## LÍNEA DE TIEMPO (15 minutos exactos)

| Minuto | Bloque | Quién habla | Contenido |
|---|---|---|---|
| 0:00 - 0:45 | Apertura | Ambos (alternando) | Presentación del equipo, ataque elegido, organización |
| 0:45 - 1:15 | Contexto de negocio | Compañero | Quién es CFP y por qué es la víctima |
| 1:15 - 5:00 | Kill Chain + operación técnica | Compañero | Las 7 fases, CVEs, cómo opera el ataque |
| 5:00 - 5:45 | Artefactos + equipos que los producen | Compañero | Puente hacia la parte SIEM |
| 5:45 - 6:15 | Fuentes de log + arquitectura Splunk | Tú (transición) | 2 fuentes, por qué esas 2 |
| 6:15 - 11:00 | Las 7 alertas | Tú | El corazón de tu parte — detalle en `07_guion_maestro_paso_a_paso.md` |
| 11:00 - 13:00 | Dashboard Detalle por Fase + línea de tiempo completa | Compañero | Cierra el kill chain visualmente |
| 13:00 - 14:00 | Plan de triage + VirusTotal | Ambos (compañero lidera, tú apoyas con Regla 7) | Confirmación de que no es FP |
| 14:00 - 15:00 | Cierre + cifras clave | Ambos | Frase de cierre conjunta |

---

## GUIÓN DETALLADO, BLOQUE POR BLOQUE

### Bloque 1 — Apertura (0:00 - 0:45)

**QUÉ DECIR (alternando, una frase cada uno):**
> *(Tú)* "Buenos días/tardes profesor. Somos [nombres], y vamos a presentar el análisis y detección
> del ataque ProxyLogon contra Microsoft Exchange Server."
>
> *(Compañero)* "Elegimos este ataque porque es real, ocurrió en marzo de 2021, fue explotado
> masivamente por el grupo HAFNIUM, y está extensamente documentado por Microsoft, Volexity y CISA
> — lo que nos permitió anclar cada parte de nuestra simulación a evidencia pública real, no
> inventada."
>
> *(Tú)* "Nuestro enfoque es Detección mediante SIEM, usando Splunk, sobre una organización
> hipotética: Corporación Financiera del Pacífico S.A."

### Bloque 2 — Contexto de negocio (0:45 - 1:15) — Compañero

**QUÉ DECIR:**
> *"CFP es una entidad financiera peruana regulada, con Exchange expuesto a internet desde 2019 para
> que la fuerza comercial accediera a su correo sin depender de VPN. Elegimos el sector financiero
> porque está confirmado como uno de los efectivamente comprometidos en la campaña real, según el
> reporte de ESET sobre los 10 grupos APT que explotaron esta vulnerabilidad."*

**Conexión con la rúbrica**: esto cubre "organización hipotética" del enunciado general del curso.

### Bloque 3 — Kill Chain + operación técnica (1:15 - 5:00) — Compañero

Usa `docs/01_kill_chain_artefactos.md` como base. Estructura sugerida (7 fases del Kill Chain de
Lockheed Martin, tal como pide la rúbrica):

1. **Reconocimiento** (30s): escaneo externo buscando Exchange vulnerable.
2. **Preparación/Weaponización** (20s): construcción del payload SSRF + webshell.
3. **Entrega** (20s): la petición HTTP maliciosa directa al servidor expuesto.
4. **Explotación** (45s): CVE-2021-26855, el SSRF explicado técnicamente — *"el frontend de
   Exchange reenvía la petición a su propio backend, autenticándose como si fuera un proceso de
   confianza."*
5. **Instalación** (45s): CVE-2021-27065, escritura del webshell vía `Set-OabVirtualDirectory`.
6. **Comando y Control** (30s): ejecución de comandos vía el webshell.
7. **Acciones sobre los objetivos** (30s): exportación de buzón, LSASS, exfiltración.

**Frase de cierre de este bloque:**
> *"Esta cadena de 4 CVEs es lo que le da nombre a todo el ataque: ProxyLogon — porque el atacante
> logra un proxy hacia un logon válido, sin necesitar credenciales reales."*

### Bloque 4 — Artefactos + equipos que los producen (5:00 - 5:45) — Compañero

**QUÉ DECIR:**
> *"Cada fase deja artefactos digitales específicos: en la red, los logs de IIS del servidor
> Exchange; en el host, el Windows Event Log del sistema operativo. Estos son producidos por el
> propio servidor — el servidor web genera los logs de red, y el sistema operativo Windows genera
> los logs de eventos y procesos. Con esto entramos a la parte de detección, que va a explicar
> [nombre]."*

**Esta frase es la transición — apréndanla los dos, textual, para que suene fluido.**

### Bloque 5 — Fuentes de log + arquitectura (5:45 - 6:15) — Tú

**QUÉ DECIR:**
> *"Usamos Splunk como SIEM, con exactamente esas dos fuentes que mencionó [compañero]: logs de IIS
> en formato W3C nativo, y Windows Event Logs. Configuramos un índice llamado proxylogon, con 296
> eventos de IIS y 32 de Windows Event Log — mezclados con tráfico benigno de empleados reales, para
> que el ejercicio de triage tenga sentido: hay que encontrar la aguja en el pajar, no una tabla ya
> filtrada."*

### Bloque 6 — Las 7 alertas (6:15 - 11:00) — Tú, el bloque más largo

Sigue `docs/07_guion_maestro_paso_a_paso.md` (Parte 4) para el detalle exacto de cada alerta.
**Presupuesto de tiempo por alerta** (para no pasarte de los ~4:45 min totales):
- Alerta 1 (SSRF): 50s
- Alerta 2 (Webshell): 40s
- Alerta 3 (C2): 45s
- Alerta 4 (Mailbox Export): 35s
- Alerta 5 (LSASS): 40s
- Alerta 6 (Validación OTRF — tu momento fuerte): 60s
- Alerta 7 (Falsos Positivos): 35s

**Sobre el correo de alerta (importante, léelo)**: dado que tuvimos problemas técnicos reales
configurando el envío automático (el SMTP de Gmail terminó enviando de más y quedó desactivado),
**la recomendación es NO depender de una demo en vivo del correo** el día de la sustentación —
mucho riesgo, poco beneficio. En su lugar:
> *"Configuramos además la acción de notificación por correo — una función nativa de Splunk que,
> en producción, avisaría automáticamente al SOC cuando se dispara una alerta. Aquí tienen la
> captura del correo real que recibimos durante nuestras pruebas."* (mostrar el screenshot del
> primer correo que sí llegó bien, con el asunto "[SOC-CFP][CRITICA] Alerta 01...").

Esto cumple con mencionar la funcionalidad (que es real y la probamos) sin arriesgarse a que falle
en vivo frente al profesor.

### Bloque 7 — Dashboard Detalle por Fase (11:00 - 13:00) — Compañero

**QUÉ DECIR:**
> *"Para cerrar el círculo del Kill Chain, este dashboard muestra cada fase con su evidencia
> específica: Fase 1, el reconocimiento externo; Fase 2, la explotación SSRF que ya vieron; Fase 3,
> la instalación del webshell; Fase 4, comando y control; Fase 5, con sus tres sub-fases —
> exportación de buzón, acceso a LSASS, y exfiltración del archivo .pst. Y este panel final junta
> las 9 etapas en una sola línea de tiempo cronológica: desde el primer escaneo a las 09:12, hasta
> la exfiltración a las 09:54 — 42 minutos de principio a fin."*

**Dato para impresionar**: *"Nuestra alerta inicial se hubiera disparado a las 09:45 — 9 minutos
antes de que el atacante lograra exfiltrar cualquier dato. Esa es la ventana real de contención que
un SOC tendría con este sistema."*

### Bloque 8 — Plan de triage + VirusTotal (13:00 - 14:00) — Ambos

**Compañero explica el proceso** (de `docs/02_plan_triage_respuesta.md`):
> *"Como Analista SOC Nivel 1, seguimos el proceso de tratamiento de alertas visto en el curso:
> evaluación inicial, triage lógico, enriquecimiento, categorización, prioridad, y escalamiento.
> Consultamos la IP 103.77.192.219 en VirusTotal — no es una IP inventada, es un IOC real de la
> campaña, documentado en el advisory CISA AA21-062A — y 10 de 91 motores de seguridad la marcan
> como maliciosa."* (mostrar screenshot de VirusTotal)

**Tú cierras con la Regla 7:**
> *"Y como el propio profesor nos pidió en la aprobación de la propuesta, confirmamos que esto no es
> un falso positivo: corrimos la misma lógica contra tráfico interno legítimo, y el resultado es
> cero. No es una afirmación — es evidencia cuantitativa."*

### Bloque 9 — Cierre (14:00 - 15:00) — Ambos

**QUÉ DECIR (alternando):**
> *(Compañero)* "En resumen: analizamos las 7 fases del Cyber Kill Chain de un ataque real y
> documentado, identificamos los artefactos digitales que deja en cada fase, y diseñamos un plan de
> respuesta alineado a NIST y a la normativa financiera peruana."
>
> *(Tú)* "Implementamos esa detección en Splunk con 7 reglas sobre 2 fuentes de log reales, validamos
> que esas reglas detectarían no solo nuestra simulación sino una ejecución genuina y pública del
> exploit, y confirmamos cuantitativamente que no generan ruido con tráfico legítimo."
>
> *(Ambos)* "Quedamos atentos a sus preguntas."

---

## CÓMO SE COMPLEMENTAN — puntos exactos donde pueden ayudarse

1. **Tú puedes reforzar el Bloque 3 (Kill Chain)** si tu compañero se traba: tienes el detalle
   técnico completo en `docs/06_explicacion_profunda_eventos.md` (glosario de IOCs, explicación de
   CVE-2021-26855 en el bloque "Regla 1").
2. **Tu compañero puede reforzar el Bloque 6 (alertas)** si el profesor pregunta algo de MITRE
   ATT&CK o kill chain durante tu parte — él conoce a fondo el mapeo de fases.
3. **Ambos deben saber la Regla 6** (validación OTRF) — es el punto más fuerte de todo el proyecto y
   cualquiera de los dos debería poder explicarlo si se lo preguntan directamente.
4. **Practiquen el Bloque 4→5 (la transición)** juntos varias veces — es el único punto donde la
   presentación cambia de orador de forma "dura"; que se sienta natural marca mucho.

---

## Checklist final antes del sábado

- [ ] Ensayo completo cronometrado (usar esta línea de tiempo con cronómetro real)
- [ ] Screenshot del correo de la Alerta 1 guardado (el que sí llegó bien)
- [ ] Screenshot de VirusTotal guardado
- [ ] Ambos repasaron `docs/04_autoexamen.md` (20 preguntas)
- [ ] Ambos saben explicar la Regla 6 (validación OTRF) sin mirar notas
- [ ] Video de respaldo de la demo completa grabado
- [ ] Confirmado: las 7 alertas visibles en Splunk, dando 7,2,4,1,1,3,0
