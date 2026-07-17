# Plan de Triage e Incidente de Seguridad

## Resumen de Artefactos Descubiertos

| Tipo                  | Valor                     |
| --------------------- | ------------------------- |
| IP maliciosa          | `139.84.168.189`          |
| Dominio / URL         | `/api/v1/buscar_producto` |
| Hashes de archivos    | No identificados          |
| Cuentas comprometidas | No identificadas          |

---

# Registro de Acciones de Triage

## Inyección 1

### Acción 1: Análisis del WAF

**Timestamp (UTC):** 2026-06-13 13:59:54

**Analista:** Alexander Abrisqueta

**Acción realizada:**

* Analizar los registros del WAF.

**Objetivo:**

* Determinar por qué el WAF no bloqueó el ataque de SQL Injection.

**Resultado / Justificación:**

* Se confirmó mediante los registros que ocurrió un ataque de SQL Injection.

**Evidencia:**

* Logs del WAF que muestran intentos exitosos de SQL Injection.

---

### Acción 2: Cambio preventivo de contraseñas

**Timestamp (UTC):** 2026-06-13 13:59:54

**Analista:** Alexander Abrisqueta

**Acción realizada:**

* Solicitar cambio inmediato de contraseñas administrativas.

**Objetivo:**

* Reducir el riesgo de acceso no autorizado en caso de que las credenciales hayan sido expuestas durante la intrusión.

**Resultado / Justificación:**

* Debido a que el servidor fue comprometido y se extrajo la base de datos de clientes, existe la posibilidad de que credenciales sensibles hayan quedado expuestas.

**Evidencia:**

* Confirmación de exfiltración de información desde la base de datos.

---

## Inyección 2

### Acción: Declaración de compromiso de datos

**Timestamp (UTC):** 2026-06-13 13:59:54

**Analista:** Alexander Abrisqueta

**Acción realizada:**

* Asumir que la información de los clientes ha sido comprometida.

**Objetivo:**

* Activar procedimientos de respuesta ante fuga de información y notificación.

**Resultado / Justificación:**

* Se verificó que el atacante obtuvo acceso a la base de datos de clientes.

**Evidencia:**

* Validación de acceso no autorizado a la base de datos.

---

## Inyección 3

### Acción: Bloqueo de red

**Timestamp (UTC):** 2026-06-13 13:59:54

**Analista:** Alexander Abrisqueta

**Acción realizada:**

* Bloquear el bloque CIDR asociado al atacante.

**Objetivo:**

* Evitar que el actor malicioso continúe operando desde direcciones IP cercanas pertenecientes al mismo proveedor o segmento.

**Resultado / Justificación:**

* Se identificó que la IP utilizada corresponde a una máquina virtual. El atacante podría destruir dicha VM y aprovisionar una nueva con otra IP cercana.
* El bloqueo del bloque CIDR reduce la probabilidad de reutilización inmediata de infraestructura similar.

**Evidencia:**

* IP identificada: `139.84.168.189`

---

# Evaluación Inicial del Incidente

## Tipo de ataque

* SQL Injection

## Activo afectado

* Aplicación web
* Base de datos de clientes

## Impacto observado

* Acceso no autorizado a la base de datos.
* Posible exfiltración de información de clientes.
* Riesgo potencial para credenciales administrativas.

## Acciones de contención ejecutadas

1. Revisión de registros del WAF.
2. Cambio preventivo de contraseñas.
3. Declaración de compromiso de datos.
4. Bloqueo del rango de red asociado al atacante.

## Indicadores de Compromiso (IoCs)

### Direcciones IP

* `139.84.168.189`

### Rutas afectadas

* `/api/v1/buscar_producto`

## Próximos pasos recomendados

1. Revisar la configuración y reglas del WAF.
2. Corregir la vulnerabilidad SQL Injection en la aplicación.
3. Rotar todas las credenciales administrativas y de servicio.
4. Revisar logs de base de datos para determinar alcance de la exfiltración.
5. Verificar integridad de sistemas comprometidos.
6. Notificar a las áreas correspondientes sobre posible fuga de datos.
7. Implementar consultas parametrizadas y validación de entradas.
8. Realizar análisis forense para identificar actividades adicionales del atacante.
