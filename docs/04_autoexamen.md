# Autoexamen — Preguntas de práctica para la sustentación

Instrucciones: cada integrante responde en voz alta, SIN mirar los documentos. Si alguno se traba,
anótenlo y repásenlo antes de la sustentación. El profesor pregunta 1 a 1 — ambos deben poder
responder cualquiera de estas.

## A. Kill Chain y operación técnica del ataque

1. **¿Qué es ProxyLogon y qué CVEs incluye?**
   → Cadena de 4 vulnerabilidades en Exchange (CVE-2021-26855, 26857, 26858, 27065), explotadas
   desde enero 2021, divulgadas por Microsoft el 2 de marzo de 2021. Grupo HAFNIUM.

2. **Explica CVE-2021-26855 sin leer nada.**
   → SSRF pre-autenticación. El atacante manda una petición HTTP con una cookie
   `X-AnonResource-Backend` falsificada y una URI manipulada con `@dominio-externo` hacia
   `/autodiscover/`. El frontend de Exchange reenvía la petición a su propio backend
   autenticándose como si fuera un proceso de confianza — así el atacante lee datos de buzones
   sin credenciales.

3. **¿Por qué se llama "ProxyLogon"?**
   → Porque el atacante logra un "proxy hacia un logon válido": usa el SSRF para que el propio
   servidor se autentique en nombre de un usuario, sin necesitar la contraseña real.

4. **¿Cómo se instala el webshell? ¿Qué CVE es?**
   → CVE-2021-27065, escritura arbitraria de archivos post-autenticación, abusando de funciones
   administrativas de ECP (`Set-OabVirtualDirectory`). Con el contexto autenticado obtenido vía
   SSRF, el atacante escribe el archivo `.aspx` en una carpeta web-accesible.

5. **¿Qué pasa después de instalar el webshell?**
   → El atacante ejecuta comandos vía POST al webshell (`w3wp.exe` genera `cmd.exe`/`powershell.exe`
   como hijo), exporta buzones con `New-MailboxExportRequest`, vuelca credenciales de LSASS con
   `procdump`, y exfiltra el `.pst` vía el mismo webshell.

6. **Mapea 3 fases al MITRE ATT&CK.**
   → T1190 (Exploit Public-Facing Application) = explotación SSRF. T1505.003 (Web Shell) =
   instalación. T1003.001 (OS Credential Dumping: LSASS Memory) = volcado de credenciales.

## B. Reglas de detección (SPL / Splunk)

7. **¿Cuáles son las 5 reglas y a qué fase corresponde cada una?**
   → 1) SSRF/bypass (explotación), 2) escritura de webshell (instalación), 3) C2 vía webshell
   (comando y control), 4) exportación de buzón (acciones sobre objetivos), 5) acceso a LSASS
   (acciones sobre objetivos / credenciales).

8. **Explica la Regla 2 en detalle — ¿qué hace el comando `transaction`?**
   → Correlaciona un POST a `/ecp/` seguido de un GET a un `.aspx` desde la misma IP en menos de
   2 minutos. `transaction` es una función nativa de Splunk para agrupar eventos relacionados en
   una secuencia — se explica como ejemplo de "propiedad propia del SIEM" en la rúbrica.

9. **¿Qué es un lookup en Splunk y cómo lo usan?**
   → Tabla de referencia externa (CSV) que Splunk cruza con los resultados de una búsqueda. La
   Regla 1 usa `lookup hafnium_ips src_ip AS c_ip OUTPUT isBad` para marcar automáticamente si la
   IP de origen coincide con una de las 16 IPs reales publicadas por Volexity/Microsoft/Huntress.

10. **¿Por qué usan `dedup` en varias reglas?**
    → Porque durante el desarrollo se cargó el dataset varias veces (mejorándolo con IOCs reales),
    y no se pudo borrar el índice de forma segura tan cerca de la entrega. `dedup` limpia esos
    duplicados del resultado final — es una práctica real de limpieza de datos.

11. **¿Qué es la Regla 6 y por qué importa más que las otras 5?**
    → No es sobre el dataset simulado, sino que corre el mismo patrón de detección (`w3wp.exe`
    generando un proceso hijo) contra un dataset **real** publicado por OTRF, capturado de una
    ejecución genuina del exploit público. Demuestra que la regla no es solo teórica — detectaría
    el ataque real.

## C. Falsos positivos y triage

12. **¿Cómo confirman que la Regla 1 no es un falso positivo?**
    → (a) Ninguna IP interna legítima genera tráfico con `@dominio-externo` hacia `/autodiscover/`.
    (b) El `time-taken` es de 8ms, consistente con una petición automatizada, no un cliente real.
    (c) Enriquecimiento con VirusTotal confirma reputación maliciosa de la IP. (d) La Regla 7
    (prueba de FP) corrió las mismas condiciones contra tráfico interno benigno y dio 0.

13. **Explica el proceso de triage paso a paso (los 6 pasos).**
    → Evaluación inicial → Triage (¿tiene sentido lógico?) → Recopilación de info adicional
    (VirusTotal) → Categorización (FP/TP) → Prioridad final → Escalamiento a Nivel 2.

## D. Organización y contexto de negocio

14. **¿Quién es la organización hipotética y por qué eligieron ese sector?**
    → Corporación Financiera del Pacífico S.A. (CFP), entidad financiera peruana. No es arbitrario:
    el sector financiero está confirmado como efectivamente comprometido en la campaña real, según
    el reporte de ESET sobre los 10 grupos APT que explotaron ProxyLogon.

15. **¿Por qué el Exchange de CFP estaba expuesto a internet?**
    → Desde 2019, para que la fuerza comercial accediera a su correo (OWA/ECP/Autodiscover) desde
    agencias y visitas a clientes sin depender de una VPN completa — decisión operativa razonable
    que amplió la superficie de ataque justo sobre el componente vulnerable.

16. **¿A quién hay que notificar en la respuesta al incidente, además del equipo técnico?**
    → SBS (Superintendencia de Banca, Seguros y AFP) por normativa de riesgo de ciberseguridad del
    sistema financiero; Autoridad Nacional de Protección de Datos Personales si hay compromiso de
    datos personales (Ley 29733); clientes afectados; Directorio y Gerencia General.

## E. Plan de respuesta al incidente

17. **Explica las 4 fases de contención/erradicación/recuperación (sin leer).**
    → Contención: bloquear IP en firewall, deshabilitar el webshell. Erradicación: eliminar el
    archivo, aplicar el parche o el Exchange On-Premises Mitigation Tool, rotar credenciales.
    Recuperación: restaurar desde imagen limpia si hay duda de persistencia, monitoreo reforzado
    30 días, validar con usuarios piloto antes de reabrir.

## F. Preguntas trampa generales

18. **¿Por qué no instalaron un Exchange real y explotaron la vulnerabilidad de verdad?**
    → Costo/beneficio: instalar Exchange requiere un Domain Controller adicional, ~20GB+ de RAM,
    y típicamente un día completo con alto riesgo de fallar en el primer intento. Además, los
    instaladores actuales de Microsoft ya vienen parchados — no se puede reproducir el exploit real
    de todas formas. En su lugar, anclamos cada patrón a IOCs y reportes reales, y validamos las
    reglas contra un dataset real (Regla 6).

19. **¿Qué pasaría si el atacante usa un nombre de webshell distinto a `help.aspx`?**
    → La Regla 2 no depende del nombre del archivo — detecta el *patrón de comportamiento*
    (POST a `/ecp/` seguido de un GET a cualquier `.aspx` nuevo en menos de 2 minutos), así que
    seguiría detectando aunque cambie el nombre.

20. **¿Qué harían distinto en un entorno de producción real?**
    → Agregar una tercera fuente (firewall/EDR), desplegar Sysmon con reglas Sigma en vez de logs
    genéricos, automatizar la respuesta con SOAR, y reducir el SLA de parcheo para activos críticos
    expuestos a internet.
