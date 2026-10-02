# 01_MASTER_SPEC.md — AISOFTWAREFACTORY · Development Orchestrator

| Campo | Valor |
|---|---|
| Documento | `01_MASTER_SPEC` |
| Versión | 0.2 |
| Estado | `APROBADO PARA CONSTRUCCIÓN` |
| Fuente de verdad | Este documento + archivos de configuración YAML |
| Ámbito | MVP local, un solo operador humano principal (Product Owner), primer piloto AIP |
| Regla rectora | `MOTOR ≠ REGLAS`: el comportamiento se cambia editando YAML, no el núcleo |

> Notas de reconciliación entre fuentes (resueltas en este documento):
> - El estado inicial se denomina **`BACKLOG`**; equivale al concepto `TASK` de la spec MVP 0.1 (la tarea entra en `BACKLOG`).
> - `DIRECTOR_REVIEW` de la spec 0.1 no es un estado persistente adicional: se modela como la **acción manual de resolución** disponible desde `BLOCKED`.
> - El archivo por proyecto se denomina **`PROJECT_RULES.yaml`**; puede residir bajo `PROJECTS/<project>/PROJECT_RULES.yaml`, compatible con el patrón `PROJECTS/<project>.yaml`.

---

## 0. Decisiones de diseño aprobadas y principios de gobernanza

### Decisiones de diseño aprobadas

- **D1 — Modo de operación del Director IA (CERRADA).** `DirectorPort = adaptador programático OpenAI API`. El Director IA opera **programáticamente vía API** para generación de especificaciones, revisión técnica y revisión de seguridad. El adaptador permanece **desacoplado del núcleo** (patrón puertos/adaptadores, §13).
- **D2 — Modelo de autoridad (CERRADA).** Los cambios AMARILLO **expresamente contemplados** los aprueba el Director mediante autoridad programada; las decisiones materiales **no contempladas** se detienen y escalan a la Product Owner. Detalle en §8.

### Principio de gobernanza

> **`AUTORIDAD PROGRAMADA ≠ DECISIÓN AUTÓNOMA IMPROVISADA`**

Una acción material puede ser aprobada por el Director **únicamente** cuando su autoridad y los límites de esa decisión están **previamente establecidos** en especificación, reglas, políticas, ADR o configuración aprobada. La regla de no-decisión autónoma prohíbe resolver decisiones materiales **no contempladas**; no impide ejercer una autoridad previamente programada. Toda decisión material nueva no contemplada obliga a **detener y escalar**.

---

## 1. Propósito y problema

**Problema.** Hoy la Product Owner (PO) actúa como intermediaria técnica: transporta manualmente prompts, especificaciones, código, errores, evidencia y correcciones entre el Director IA (OpenAI) y el desarrollador (Claude Code). Es lento, propenso a error y exige conocimiento técnico que no debe requerirse de la PO.

**Intervención humana que se elimina.** El transporte manual de artefactos técnicos entre modelos y la conducción manual del ciclo desarrollar → probar → revisar → corregir.

**Intervención humana que se conserva.** Decisiones materiales de negocio y validación visual/funcional, concentradas en los Human Gates. La PO expresa una necesidad y, al final, responde `APROBADO` o describe el problema.

**Objetivo del MVP.** Demostrar de extremo a extremo, sin transporte manual:

```
NECESIDAD → SPEC → CLAUDE CODE → TEST → REVIEW → FIX → APROBACIÓN TÉCNICA → HUMAN_GATE
```

---

## 2. Roles

**Product Owner (PO).** Expresa necesidades, toma decisiones de negocio, realiza pruebas visuales/funcionales, aprueba o rechaza en Human Gates. No intermedia técnicamente ni conduce el ciclo de corrección.

**Director IA.** Proveedor OpenAI accedido mediante **adaptador programático de API** (`DirectorPort`, desacoplado del núcleo; D1 en §0). Convierte necesidades en especificaciones ejecutables (Task Packet), controla alcance, ejecuta revisión técnica y revisión de seguridad y determina aprobación técnica o corrección. Ejerce **autoridad de dirección técnica dentro de los límites del motor**, incluida la aprobación de cambios AMARILLO **expresamente contemplados** (§8). No puede alterar las reglas del motor ni resolver por sí mismo decisiones materiales **no contempladas**: en ese caso detiene y escala a la Product Owner (§8, §9).

**Orquestador (motor).** Proceso local. Controla estados, permisos, comunicación entre agentes, ejecución de pruebas, captura de evidencia, límites de iteración y Human Gates. No razona sobre producto: **hace cumplir reglas**. No es modificable por los modelos.

**Claude Code.** Desarrollador. Implementa **exclusivamente** el Task Packet autorizado. No decide producto, arquitectura, seguridad, permisos, infraestructura ni alcance.

**Agentes futuros.** Solo como extensión detrás de los mismos puertos/contratos (§13). Fuera del MVP.

---

## 3. Alcance del MVP

El MVP debe, para una tarea de bajo riesgo sobre el repositorio de un proyecto piloto:

1. Registrar una necesidad de la PO como tarea.
2. Generar automáticamente una especificación ejecutable (Task Packet) mediante el Director IA.
3. Entregar el Task Packet a Claude Code y obtener una implementación.
4. Ejecutar automáticamente pruebas, lint, TypeScript y build cuando apliquen, capturando evidencia ejecutable.
5. Ejecutar revisión técnica y revisión de seguridad automáticas, contrastadas contra evidencia (no solo narrativa del agente).
6. Ante un fallo, transitar a `CHANGES_REQUESTED` y reenviar corrección a Claude Code automáticamente, hasta un límite configurable de intentos.
7. Alcanzar `TECH_APPROVED` cuando se cumplan criterios técnicos y de seguridad.
8. Presentar un `HUMAN_GATE` donde la PO responde `APROBADO` o describe el problema, y **enviar un aviso saliente simple** (Slack Incoming Webhook) al entrar en él; el aviso es solo un canal, SQLite sigue siendo la fuente de verdad (§9).
9. Confirmar el cambio en una **rama de tarea** (sin push, sin merge, sin producción) y cerrar la tarea.
10. Persistir toda la traza en SQLite de forma reconstruible.

Todo esto en ejecución **local**, un proceso, un operador.

---

## 4. Fuera de alcance (deliberado)

Dashboard avanzado · SaaS · multiusuario · marketplace de agentes · multiagente avanzado · facturación · infraestructura distribuida (Kubernetes, Docker, colas, Redis, servidores) · despliegue automático a producción · aplicación móvil · sistema complejo de notificaciones (aprobaciones entrantes, bot interactivo, botones, múltiples canales, motor de mensajería; el **aviso saliente simple** de un Human Gate SÍ está dentro del MVP, §3.8 y §9) · integraciones empresariales no necesarias para demostrar el ciclo · `git push`, `git merge` y cualquier operación sobre producción · eliminaciones irreversibles · gestión de credenciales de terceros.

---

## 5. Flujo completo y estados

### 5.1 Estados

`BACKLOG` · `SPECIFICATION` · `DEVELOPING` · `WAITING_FOR_CLAUDE_CAPACITY` · `AUTOMATED_TEST` · `TECHNICAL_REVIEW` · `SECURITY_REVIEW` · `CHANGES_REQUESTED` · `TECH_APPROVED` · `HUMAN_GATE` · `HUMAN_APPROVED` · `READY_FOR_COMMIT` · `COMPLETED` · `BLOCKED`

### 5.2 Transiciones permitidas

| Estado | Actor / mecanismo | Sale hacia (condición) |
|---|---|---|
| `BACKLOG` | PO registra necesidad | `SPECIFICATION` (el Director toma la tarea) |
| `SPECIFICATION` | Director genera Task Packet; motor lo valida contra PERMISSIONS/POLICIES | `DEVELOPING` (packet válido) · `BLOCKED` (decisión material / contradicción / alcance indefinido) |
| `DEVELOPING` | Claude Code implementa el packet | `AUTOMATED_TEST` (ejecución finalizada) · `WAITING_FOR_CLAUDE_CAPACITY` (señal estructurada de capacidad de Claude) · `BLOCKED` (condición de parada §18/§ reglas) |
| `WAITING_FOR_CLAUDE_CAPACITY` | Espera automática temporal después de una señal estructurada de capacidad de Claude; el motor no cuenta la espera como intento funcional | `DEVELOPING` (se reanuda la misma tarea) · `BLOCKED` (límite de espera o de reintentos superado, o continuidad no demostrable) |
| `AUTOMATED_TEST` | Motor: tests, lint, TypeScript, build | `TECHNICAL_REVIEW` (todo verde) · `CHANGES_REQUESTED` (algún fallo) |
| `TECHNICAL_REVIEW` | Director revisa evidencia (diff, resultados, archivos modificados) y aprueba AMARILLO **contemplado** por autoridad programada (§8) | `SECURITY_REVIEW` (ok) · `CHANGES_REQUESTED` (hallazgos) · `BLOCKED` (decisión material no contemplada) |
| `SECURITY_REVIEW` | Motor (checks deterministas, autoritativos) + Director (revisión) | `TECH_APPROVED` (ok, incluida aprobación de AMARILLO contemplado) · `CHANGES_REQUESTED` (hallazgos) · `BLOCKED` (decisión material no contemplada) · `HUMAN_GATE` (acción ROJO no prohibida) |
| `CHANGES_REQUESTED` | Motor prepara corrección derivada de la evidencia | `DEVELOPING` (intentos < límite) · `BLOCKED` (intentos ≥ límite) |
| `TECH_APPROVED` | Motor confirma criterios técnicos + seguridad | `HUMAN_GATE` |
| `HUMAN_GATE` | PO revisa (§9) | `HUMAN_APPROVED` (`APROBADO`) · `CHANGES_REQUESTED` (describe problema) · `BLOCKED` (decisión de negocio no resuelta) |
| `HUMAN_APPROVED` | — | `READY_FOR_COMMIT` |
| `READY_FOR_COMMIT` | Motor confirma en rama de tarea (nunca push, nunca merge, nunca producción) | `COMPLETED` |
| `COMPLETED` | — | *(terminal, éxito)* |
| `BLOCKED` | Decisión material no contemplada: el Director prepara alternativas y las traduce a lenguaje de negocio. Límite de intentos superado: resolución del Director (`DIRECTOR_REVIEW`) | `HUMAN_GATE` (decisión material escalada a la PO) · `SPECIFICATION` · `CHANGES_REQUESTED` · *(cierre manual)* |

**Invariante.** Toda transición se persiste como evento (`status_event`, §12) con `from`, `to`, `reason`, `actor`, `timestamp`.

---

## 6. Task Packet (contrato Director → desarrollador)

Contrato mínimo, autosuficiente y **sin contexto innecesario**. El desarrollador no recibe conversaciones completas.

| Campo | Descripción |
|---|---|
| `task_id` | Identificador único de la tarea |
| `project_id` | Proyecto al que pertenece (resuelve `PROJECT_RULES.yaml`) |
| `objetivo` | Resultado esperado, en términos verificables |
| `alcance` | Qué está incluido |
| `fuera_de_alcance` | Qué está explícitamente excluido |
| `archivos_permitidos` | Globs/paths que Claude Code puede modificar |
| `archivos_prohibidos` | Globs/paths que no puede tocar |
| `restricciones` | Límites técnicos y de estilo aplicables |
| `criterios_de_aceptacion` | Condiciones objetivas de éxito, verificables |
| `criterios_de_seguridad` | Requisitos de seguridad exigidos para esta tarea |
| `pruebas_obligatorias` | Comandos/pruebas que deben ejecutarse y pasar |
| `reglas_de_parada` | Condiciones que obligan a detener y escalar |
| `evidencia_requerida` | Artefactos ejecutables que deben adjuntarse (diff, salidas de test, etc.) |

Ejemplo de contrato (formato, no implementación):

```yaml
task_id: AIP-0001
project_id: AIP
objetivo: "…"
alcance: ["…"]
fuera_de_alcance: ["…"]
archivos_permitidos: ["src/…", "tests/…"]
archivos_prohibidos: ["**/.env*", "infra/**", "**/migrations/**"]
restricciones: ["sin nuevas dependencias", "sin cambios de esquema"]
criterios_de_aceptacion: ["…"]
criterios_de_seguridad: ["sin secretos en código", "sin cambios de permisos"]
pruebas_obligatorias: ["<cmd_test>", "<cmd_lint>"]
reglas_de_parada: ["archivo no autorizado", "dependencia nueva", "decisión material"]
evidencia_requerida: ["git_diff", "test_output", "lint_output"]
```

---

## 7. Motor de políticas (qué gobierna cada archivo)

| Archivo | Responsabilidad |
|---|---|
| `POLICIES.yaml` | Reglas generales e invariantes del sistema: prohibiciones absolutas (producción, irreversibles, secretos), límite de intentos de corrección, clasificación de autonomía por defecto, separación motor/reglas. |
| `AGENTS.yaml` | Roster de agentes: qué proveedor/modelo cumple cada rol (Director → adaptador OpenAI; Desarrollador → Claude Code CLI), capacidades y límites por agente. |
| `GATES.yaml` | Qué transiciones exigen qué aprobación; criterios de aprobación técnica; **gate interno de aprobación del Director** para AMARILLO contemplado; qué condiciones (decisión material no contemplada) escalan a `HUMAN_GATE` y de qué tipo. |
| `PERMISSIONS.yaml` | Mínimo privilegio: comandos permitidos, globs de archivos permitidos/prohibidos, herramientas por rol. |
| `PROJECT_RULES.yaml` (por proyecto) | Ruta del repositorio, comandos de test/lint/tsc/build, rutas protegidas, overrides de autonomía específicos del proyecto (p. ej. AIP). |

Regla de composición: al **agregar un proyecto** solo se añade su `PROJECT_RULES.yaml`; el núcleo del motor no se modifica. Ningún agente puede editar estos archivos.

---

## 8. Niveles de autonomía y cómo los hace cumplir el motor

Rige el principio de gobernanza `AUTORIDAD PROGRAMADA ≠ DECISIÓN AUTÓNOMA IMPROVISADA` (§0). El sistema **minimiza deliberadamente** la intervención técnica humana: no existe un rol permanente de "operador técnico humano".

### VERDE

Ejecución automática por el motor dentro de una tarea autorizada: lectura del repo; modificación de `archivos_permitidos`; tests, lint, TypeScript, build; correcciones directamente derivadas de pruebas o de una revisión aprobada.

**Control del motor:** validación del Task Packet + inspección del diff post-ejecución (todo dentro de `archivos_permitidos` y `PERMISSIONS.yaml`).

### AMARILLO CONTEMPLADO

El Director IA está **autorizado a aprobar o rechazar** cambios AMARILLO (migraciones, dependencias relevantes, cambios arquitectónicos, modelo de datos, RLS, autenticación, autorización, roles, funciones privilegiadas) **únicamente cuando se cumplen todas** las condiciones:

- la operación está **expresamente contemplada** por la especificación o las reglas;
- está dentro del **alcance autorizado**;
- existe **evidencia suficiente** (§11);
- cumple los **criterios técnicos y de seguridad**;
- **no** implica seleccionar unilateralmente una nueva alternativa material no prevista.

Ejemplos: una migración incluida expresamente en el Task Packet; un cambio RLS expresamente especificado; una dependencia previamente autorizada; un cambio de autenticación expresamente definido. En estos casos el Director ejerce **autoridad programada**, no una decisión autónoma improvisada.

**Control del motor:** la aprobación se resuelve en el **gate interno de aprobación del Director** (`GATES.yaml`) durante `TECHNICAL_REVIEW`/`SECURITY_REVIEW`, contra la evidencia. No requiere intervención humana.

### DECISIÓN MATERIAL NO CONTEMPLADA

Si en cualquier estado aparece una decisión material **no prevista** en especificación, reglas, políticas, ADR o configuración aprobada, **ningún agente puede resolverla unilateralmente**. Flujo:

```
BLOCKED
  → el Director identifica el problema
  → presenta alternativas
  → recomienda una opción
  → explica impacto y riesgo en lenguaje comprensible para la Product Owner
  → HUMAN_GATE
  → la Product Owner decide
```

La Product Owner **no** debe analizar código, SQL, comandos, diffs ni detalles técnicos para decidir. El Director **transforma** la cuestión técnica en una decisión comprensible.

### ROJO

Requiere **aprobación explícita de la Product Owner** (`HUMAN_CRITICAL_APPROVAL`): producción, eliminación irreversible, credenciales, facturación, cambio de proveedor, incrementos materiales de costos, cambios funcionales importantes no contemplados. Las operaciones ROJO **prohibidas por el MVP** continúan simplemente **prohibidas** (parada dura), no solo bloqueadas.

### Mecanismos de detección (deterministas)

Clasificación del cambio a partir de `git diff`, archivos tocados vs `archivos_permitidos`, aparición de dependencias nuevas (diff de manifiestos), cambios en archivos de entorno/permisos/migraciones/RLS. Todo cambio se clasifica **antes** de avanzar de estado; el motor decide entonces entre ejecución VERDE, gate interno del Director (AMARILLO contemplado), `BLOCKED`+escalado (material no contemplado) o Human Gate PO (ROJO).

---

## 9. Human Gates

| Gate | Cuándo se dispara | Acción de la PO |
|---|---|---|
| `HUMAN_UI_REVIEW` | El cambio afecta interfaz visible | Revisa visualmente → `APROBADO` o describe el problema |
| `HUMAN_FUNCTIONAL_TEST` | El cambio afecta comportamiento funcional | Prueba funcionalmente → `APROBADO` o describe el problema |
| `HUMAN_BUSINESS_DECISION` | Decisión material **no contemplada** (llega desde `BLOCKED`, ya traducida por el Director a alternativas + recomendación + impacto/riesgo en lenguaje de negocio) | Decide (elige alternativa) |
| `HUMAN_CRITICAL_APPROVAL` | Acción clasificada ROJO no prohibida | Aprueba o rechaza explícitamente |

Regla de interacción: la PO debe poder resolver el gate respondiendo simplemente `APROBADO` o con una descripción del problema. Un problema descrito genera `CHANGES_REQUESTED`; una decisión no resuelta genera `BLOCKED`. **La PO nunca analiza código, SQL, comandos ni diffs**: el Director es responsable de transformar toda cuestión técnica escalada en una decisión comprensible.

**Aviso saliente:** al entrar en `HUMAN_GATE` (tras `run-task`, `resume-capacity` o `resume-due`), el motor intenta UN aviso saliente mediante `NotifierPort` (adapter de Slack Incoming Webhook, solo salida). El aviso contiene únicamente `project_id`, `task_id`, el tipo de gate, el texto estático de `GATES.yaml` y un estado fijo; nunca código, diffs, contenido de archivos, Task Packet ni salida de Claude. Semántica *at-most-once* (sin reintentos automáticos), un intento por entrada al gate (`status_event`), registrado en `notification_event`. Un fallo del aviso **nunca** cambia la tarea ni el resultado: sigue en `HUMAN_GATE`. La URL del webhook es un secreto que solo vive en una variable de entorno (nombre configurado en `config/NOTIFICATIONS.yaml`, opcional). Fuera de alcance: aprobar desde Slack, botones, eventos entrantes, bot interactivo, múltiples canales.

---

## 10. Seguridad (controles mínimos desde el MVP)

- **Secretos:** nunca en prompts, repos, logs ni base de datos. Task Packet mínimo; redacción/enmascarado en logs; escaneo de secretos en el diff antes de aprobar.
- **Permisos y comandos:** solo lo declarado en `PERMISSIONS.yaml`; mínimo privilegio; comandos fuera de lista → parada.
- **Archivos:** Claude Code solo modifica `archivos_permitidos`; cualquier archivo fuera de lista detectado en el diff → parada.
- **Producción prohibida** y **acciones irreversibles prohibidas** en el MVP.
- **Dependencias:** dependencia nueva → AMARILLO (no se instala automáticamente).
- **Autenticación / autorización / RLS:** cuando apliquen, son AMARILLO; se revisan en `SECURITY_REVIEW`.
- **Revisión del diff:** obligatoria e independiente en cada ejecución.
- **Logging sin datos sensibles:** los eventos registran referencias/resúmenes, no secretos ni PII.
- **Aislamiento:** en escenarios multicliente (fuera del MVP) debe garantizarse aislamiento total; se documenta como principio, no se implementa aquí.
- **Errores seguros:** ante ambigüedad o contradicción de reglas, el sistema falla cerrado (parada), no abierto.

---

## 11. Verificación independiente

El orquestador **no confía en la narrativa** de los agentes: comprueba directamente y guarda la evidencia.

| Comprobación | Mecanismo |
|---|---|
| Estado Git | `git status` |
| Cambios reales | `git diff` |
| Archivos modificados | lista derivada del diff, contrastada con `archivos_permitidos` |
| Tests | ejecución de `pruebas_obligatorias` / comandos de `PROJECT_RULES.yaml` |
| Lint | comando de lint del proyecto (si aplica) |
| TypeScript | `tsc`/comando de type-check (si aplica) |
| Build | comando de build del proyecto (si aplica) |
| Dependencias | diff de manifiestos (p. ej. `package.json`/lockfile) |
| Archivos de entorno | detección de `.env*` en el diff |
| Posibles secretos | escaneo por patrón/entropía sobre el diff |

**Git es la fuente técnica de verdad.** Los informes de los agentes son insumo, no evidencia.

---

## 12. Persistencia (modelo conceptual mínimo, SQLite)

Entidades (campos clave; todas con timestamps `created_at`/`updated_at` según corresponda):

- `project` (id, name, repo_path, rules_ref)
- `task` (id, project_id, title, need_text, status, attempt_count)
- `specification` (id, task_id, task_packet_json, author, version)
- `agent_run` (id, task_id, agent, role, phase, input_ref, output_ref, exit_status, started_at, ended_at)
- `status_event` (id, task_id, from_status, to_status, reason, actor)
- `task_suspension` (task_id, task_packet_path, task_packet_sha256, project_rules_sha256, permissions_sha256, baseline_head_sha, baseline_branch, working_tree_fingerprint, touched_paths_json, capacity_wait_count, capacity_wait_started_at, next_retry_at) — suspensión temporal de una tarea en `WAITING_FOR_CLAUDE_CAPACITY` (§5.2) por una señal estructurada de capacidad de Claude. Una fila activa por tarea; guarda solo identidad del Task Packet y de la configuración relevante mediante hashes, baseline Git original, huella del working tree, contador y tiempos de espera; nunca datos de Claude (stdout, stderr, resultado, sesión, uso, prompt) ni contenido de archivos
- `notification_event` (id, task_id, status_event_id, event_type, provider, gate_type, status[`ATTEMPTING`|`SENT`|`FAILED`], error_category, attempted_at, completed_at; único por status_event_id + event_type + provider) — intento de aviso saliente al entrar en un Human Gate. Guarda solo metadata mínima y vocabulario fijo; nunca el mensaje, la URL del webhook, la respuesta remota, el Task Packet ni datos de Claude
- `modified_file` (id, agent_run_id, path, change_type)
- `test_result` (id, agent_run_id, kind[`test`|`lint`|`tsc`|`build`], passed, summary_ref)
- `review_result` (id, task_id, phase[`technical`], verdict, findings_ref)
- `security_result` (id, task_id, verdict, findings_ref)
- `decision` (id, task_id, type[`material`|`business`|`critical`], description, options_ref, chosen, decided_by)
- `approval` (id, task_id, gate_type, verdict, actor, note)
- `git_commit` (id, task_id, branch, sha, message)

Los campos `*_ref` apuntan a evidencia almacenada (archivo/artefacto), no a secretos. **Las conversaciones no son la única fuente de trazabilidad.**

---

## 13. Arquitectura mínima

Un solo proceso Python, ejecución local, patrón **puertos y adaptadores** para desacoplar proveedores. Sin microservicios.

```
                    ┌──────────────────────────────────────────┐
   PO ──CLI──▶      │            ORQUESTADOR (core)             │
 Operador ─CLI─▶    │  state_machine · policy_engine · gates    │
                    └───────┬───────────────┬──────────────┬────┘
                            │               │              │
                 config/loader        persistence     verifier/runner
              (POLICIES, AGENTS,      (sqlite3)       (test/lint/tsc/
               GATES, PERMISSIONS,                     build + diff +
               PROJECT_RULES)                          secret/perm scan)
                            │
        ┌───────────────────┼─────────────────────────┐
        ▼                   ▼                          ▼
 DirectorPort         DeveloperPort               GitPort
 (adapters/           (adapters/                  (adapters/
  director_openai)     developer_claude_code)      git · subprocess)
```

**Componentes:**
- `core/state_machine` — estados y transiciones (§5).
- `core/policy_engine` — carga YAML, clasifica acciones VERDE/AMARILLO/ROJO, evalúa condiciones de parada.
- `config/loader` — lee y valida los cinco archivos YAML; `NOTIFICATIONS.yaml` es un sexto archivo OPCIONAL (ausente = avisos desactivados) que solo nombra la variable de entorno del webhook, nunca su valor.
- `persistence/store` — SQLite vía `sqlite3` (biblioteca estándar).
- `verifier/runner` — ejecuta verificación independiente (§11) y captura evidencia.
- `gates/cli` — interacción con la Product Owner (Human Gates). El gate interno de aprobación del Director (AMARILLO contemplado) no requiere intervención humana. No existe rol permanente de operador técnico humano.
- `app` — driver del ciclo (bucle que avanza estados).

**Puertos (contratos):** `DirectorPort` (generar spec, revisar técnica, revisar seguridad), `DeveloperPort` (implementar Task Packet), `GitPort` (status, diff, branch, commit), `NotifierPort` (`notify(event)`: aviso saliente de Human Gate; adapter `adapters/slack_notifier`, el motor no importa Slack). Cambiar de proveedor = cambiar de adaptador, no el núcleo.

Tecnologías: **Python · SQLite · YAML/JSON · Git · Claude Code CLI · OpenAI API (vía adaptador) · ejecución local.** No se introducen otras.

---

## 14. Ciclo de corrección

### RESOURCE-BUDGET-001 — fundamento operativo

`POLICIES.yaml.resource_budget` define perfiles separados de la autonomía:
economy (Builder 2, Verifier 1, correcciones 1, total 3), standard
(3, 2, 2, 5) y high_assurance (4, 3, 3, 7). El perfil predeterminado es
standard en la política actual. Los nombres de perfiles y el default se
resuelven exclusivamente desde POLICIES.yaml, no desde constantes del motor.
El Task Packet acepta `resource_profile` opcional; su ausencia utiliza el
default configurado, sin overrides numéricos. El techo global de correcciones
sigue siendo `attempts.max_correction_attempts`; el efectivo es el mínimo
del global y el perfil. Ningún presupuesto concede permisos ni omite gates,
seguridad, alcance, reconciliación, evidencia o pruebas obligatorias.

El Developer actual cuenta como builder; no se incorpora ningún proveedor
nuevo ni se invoca un Verifier en este incremento. `agent_run` reserva en
SQLite una unidad del rol y del total antes del lanzamiento operacional.
Reserva, conteo y comprobación son atómicos. RESERVED sin resultado, éxito,
fallo, timeout y señal de capacidad consumen igualmente. No hay reembolso
automático ni reinicio de contadores al reanudar. Se registran únicamente
identidad de tarea/agente/proveedor, rol, fase, perfil, límites efectivos,
ordinal, estado y tiempos; nunca prompts, conversaciones o salidas crudas.
El perfil queda fijo por tarea y aumentos posteriores de política no amplían
su presupuesto ya reservado; límites más restrictivos siguen aplicándose.

La ejecución inicial no es corrección. Una reserva Builder desde
CHANGES_REQUESTED consume una corrección; la reanudación por capacidad no.
La API de Store admite esta transición sin introducir un ciclo autónomo.
El agotamiento operacional bloquea con un motivo explícito y cero llamadas
adicionales. Las comprobaciones locales aplicables preceden la reserva.

Los probes diagnósticos manuales y stateless quedan fuera de presupuestos
por tarea: conservan límites por invocación, sin Store ni reintentos
automáticos. El ciclo autónomo no puede utilizarlos para eludir presupuestos.
La deduplicación de candidatos de revisión queda para la integración Verifier.

```
DEVELOPING → AUTOMATED_TEST → TECHNICAL_REVIEW → SECURITY_REVIEW
        ▲                                              │
        └──────────── CHANGES_REQUESTED ◀──────────────┘  (si falla algún paso)
```

- Cada fallo de test/revisión/seguridad genera `CHANGES_REQUESTED` con la **evidencia** del fallo (no una descripción narrativa).
- El motor incrementa `attempt_count` y reenvía a `DEVELOPING` la corrección derivada.
- Existe un **límite configurable** de intentos (`POLICIES.yaml`). Al superarlo: `BLOCKED` → resolución del Director (`DIRECTOR_REVIEW`).
- **La PO no participa** en este ciclo técnico.

---

## 15. Piloto AIP

- AIP es el primer proyecto de validación. El orquestador **no modifica su arquitectura ni su alcance** por iniciativa propia; solo coordina tareas autorizadas.
- La configuración de AIP vive en `PROJECT_RULES.yaml`: `repo_path`, comandos de test/lint/tsc/build, rutas protegidas, overrides de autonomía.
- La primera prueba debe ser una tarea **pequeña, reversible y de bajo riesgo** (nivel VERDE), sobre archivos claramente autorizados, sin migraciones, dependencias ni cambios de esquema/permisos.
- La tarea concreta **no se selecciona aún** en este documento.

---

## 16. Criterios de aceptación del MVP

Objetivos y verificables:

1. El sistema registra una necesidad y genera automáticamente un Task Packet válido **sin intervención técnica de la PO**.
2. Entrega automática del packet a Claude Code y obtención de una implementación.
3. Ejecución automática de pruebas/lint/tsc/build (según aplique) con evidencia capturada.
4. Revisión técnica y de seguridad automáticas producen veredicto **contrastado contra evidencia**, no solo narrativa.
5. Ante un fallo (incluido uno inyectado a propósito), el sistema transita a `CHANGES_REQUESTED` y reenvía corrección **automáticamente** (≥ 1 iteración) sin la PO.
6. Alcanza `TECH_APPROVED` con criterios técnicos y de seguridad cumplidos.
7. Presenta un `HUMAN_GATE` resoluble con `APROBADO` o con una descripción del problema.
8. Confirma en rama de tarea (sin push, sin merge, sin producción) y cierra en `COMPLETED`.
9. Toda la traza (estados, runs, evidencia, decisiones, aprobaciones, commit) queda **persistida y reconstruible** en SQLite.
10. **Cero secretos** en prompts, logs o base de datos; **ninguna** acción de producción o irreversible ejecutada.

**Criterio principal:** el orquestador completa **automáticamente el ciclo técnico hasta `HUMAN_GATE`** en una tarea VERDE del piloto AIP.

---

## 17. Roadmap mínimo (incrementos, sin estimaciones)

| Incremento | Entregable |
|---|---|
| **BOOTSTRAP** | Núcleo, `config/loader`, esquema SQLite, máquina de estados, CLI mínima; carga de los cinco YAML. |
| **CLAUDE EXECUTION** | `DeveloperPort` + adaptador Claude Code CLI: entregar Task Packet y recibir cambios en el repo. |
| **EVIDENCE** | `verifier/runner`: `GitPort`, ejecución de tests/lint/tsc/build, captura de diff/salidas, escaneo de secretos y permisos. |
| **REVIEW/FIX LOOP** | `DirectorPort` (revisión técnica y de seguridad) + `CHANGES_REQUESTED` con límite de intentos y `BLOCKED`. |
| **HUMAN GATE** | Gates de PO (`APROBADO`/problema), `READY_FOR_COMMIT`, commit en rama, `COMPLETED`. |
| **AIP PILOT** | Configuración `PROJECT_RULES.yaml` de AIP y ejecución del ciclo completo sobre una tarea VERDE. |

---

## 18. Riesgos materiales del MVP y mitigación

| Riesgo | Mitigación |
|---|---|
| Falsa confianza en informes narrativos de los agentes | Verificación independiente ejecutable (§11); Git como verdad. |
| Fuga de secretos en prompts/logs/DB | Task Packet mínimo, redacción en logs, escaneo del diff, prohibición de secretos en DB/logs. |
| Claude Code modifica archivos fuera de alcance | `archivos_permitidos`/`PERMISSIONS.yaml` + inspección del diff post-run + parada. |
| Bucle de corrección infinito / costo descontrolado | Límite configurable de intentos → `BLOCKED`. |
| El Director resuelve por sí mismo una decisión material **no contemplada** | Principio `AUTORIDAD PROGRAMADA ≠ DECISIÓN AUTÓNOMA IMPROVISADA`: solo aprueba AMARILLO expresamente contemplado con evidencia; todo lo no previsto → `BLOCKED` → traducción a negocio → Human Gate PO (§8). |
| Acción irreversible o de producción | Clasificación ROJO + prohibición en MVP; commit solo en rama, sin push, sin merge. |
| Contradicción entre reglas | Fallo cerrado: parada + `BLOCKED`. |
| Indisponibilidad/latencia de la API del Director | Reintentos acotados; estados persistidos para reanudar sin perder traza. |

---

## DECISIONES REQUERIDAS

No se identificaron decisiones materiales pendientes para iniciar el MVP.


## 19. ROLE-CAPABILITY-001: asignación y capacidad

El motor distingue rol funcional (`director`, `builder`, `verifier`), identidad
(clave del roster), proveedor, adaptador y capacidad. El agente compatible
`developer` tiene rol `builder`, proveedor `claude_code_cli` y adaptador explícito
`claude_code_cli`. La única combinación operacional implementada sigue siendo
ese proveedor/adaptador; no hay imports dinámicos ni selección desde Task Packets.
Los nombres Developer, probes y estados de capacidad se conservan.

AGENTS.yaml selecciona exactamente un Builder habilitado cuando se requiere
implementación. Cero o múltiples candidatos bloquean; roles/adaptadores no
soportados y combinaciones incompatibles fallan cerrado. Director sigue
inhabilitado; un Verifier inhabilitado es representable sin inventar proveedor.

PERMISSIONS.yaml declara `role_capabilities.builder` con
`implement_authorized_changes`. Esta condición adicional se comprueba antes de
reservar presupuesto o invocar implementación. Ni rol, proveedor ni adaptador
conceden autoridad. La capacidad se intersecta con alcance del Task Packet,
reglas del proyecto, rutas protegidas, comandos y controles de seguridad;
no concede Git, comandos de tests/build al modelo, administración de bases de
datos, producción, despliegue, cambios de permisos ni gobernanza.

El ledger existente registra rol, identidad y proveedor resueltos, sin cambiar
su esquema ni límites. Reanudación vuelve a validar asignación y capacidad;
no puede cambiar la identidad/proveedor del Builder registrado anteriormente.

Contrato futuro, no operativo: revisión independiente vinculará rol `verifier`,
identidad autorizada, nuevo run de Verifier y candidato exacto revisado. Su
identidad deberá diferir de todos los Builders que produjeron ese candidato;
proveedor y adaptador deberán coincidir con la asignación validada. Diversidad
de proveedor podrá exigirse por política futura de gate/proyecto; no es una
invariante universal del motor. Verifier emitirá hallazgos y veredicto, nunca
permisos, ampliación de alcance, producción ni aprobación de Human Gate.
Motor/Director aplican política y gates; la autoridad del Director no cambia.
Este incremento no invoca Director/Verifier, reserva runs de Verifier ni genera
evidencia de revisión independiente. TECHNICAL_REVIEW y SECURITY_REVIEW
continúan siendo checks/estados deterministas; GATES.yaml no cambia.

## 20. CODEX-ADAPTER-001: fundamento CLI sin activación

Se implementa la combinación cerrada `openai_codex` / `codex_cli`, con identidad
`codex_builder` y rol `builder`. La entrada canónica permanece `enabled: false`;
`developer`/Claude sigue siendo el único Builder habilitado. No hay fallback,
imports dinámicos, nuevo permiso, proveedor operacional activo ni modelo Verifier.

AGENTS.yaml conserva los ajustes Codex: ejecutable estable `codex`, timeout de
600 segundos, `workspace-write`, aprobación `never`, JSONL, ejecución efímera,
configuración personal ignorada y red del sandbox deshabilitada. No se configura
modelo ni max_turns. El proceso usa argv, `shell=False`, cwd explícito e instrucción
por stdin. No se inyectan credenciales ni se leen archivos de autenticación.
El hijo Codex recibe un entorno explícito por allowlist: PATH/PATHEXT para
resolución de ejecutables, SYSTEMROOT para Windows, USERPROFILE/HOME/CODEX_HOME
para ubicación del home y autenticación local, y TEMP/TMP para temporales.
Solo se copian valores presentes, conservando casing; no se heredan variables
de aplicación ni API keys. Contexto Windows esencial ausente bloquea sin fallback
al entorno completo. No se registran valores ni se inspecciona el almacén auth.
Los overrides de invocación excluyen raíces adicionales y temporales de escritura
y deshabilitan web search; su eficacia real en Windows debe validarse al activar.

El parser aislado exige JSONL válido, inicio y cierre terminal reconocido de una
única invocación, exit 0 y ausencia de terminales contradictorios/incompletos.
El resultado solo contiene metadatos sanitizados. No persiste stdout/stderr,
mensajes, razonamiento ni sesiones. AUTH_UNAVAILABLE, TEMPORARY_CAPACITY y
RESOURCE_LIMIT quedan reservados hasta verificar señales estructuradas estables;
no se infieren de texto libre. Fallos desconocidos bloquean sin reintento.

El motor conserva resolución/capacidad, reserva durable previa al subprocess,
consumo tras resultado incierto, evidencia, mandatory tests y Human Gates. El
adaptador no decide política ni escribe Store. Cada unidad usa una invocación
fresca; nunca `exec resume` ni `--last`. El flujo Claude permanece implementado.
Handshake/write-probe Codex fallan cerrado hasta activación; los probes canónicos
continúan usando Claude. El task-execution-probe comparte dispatch y controles,
pero no tiene reservas ni reintentos, como antes.

workspace-write permite comandos locales: serían ayudas de implementación,
nunca verificación autoritativa. Las instrucciones de no asumir Git, deploy,
producción, gobernanza o aprobación final no son una barrera técnica. El permiso
para comandos Codex queda condicionado a CODEX-ACTIVATION-001, no activa una
excepción operacional en este incremento. El alcance exacto de archivos sigue
requiriendo comprobación del motor; esta tarea no corrige protected_paths.

Bloqueos de activación explícitos:
- `CODEX_ACTIVATION_BLOCKER_PROTECTED_PATHS`: RESOLVED_BY_ENGINE_PROTECTED_PATH_SNAPSHOT_AND_SCOPE_ENFORCEMENT
  en Phase A; control detectivo durante validación del Orquestador, no aislamiento
  preventivo del sandbox (ver §21).
- `CODEX_ACTIVATION_BLOCKER_AUTH_UNVERIFIED`: AUTH_STATE permanece UNKNOWN.
- Validar sandbox Windows, red, raíces, configuración efectiva y contrato real
  de eventos de la CLI alpha; aún no se ejecutó ningún smoke de modelo real.
- El timeout del padre termina y espera al hijo directo mediante subprocess.run;
  limpieza de descendientes no está garantizada. Resolver o aceptar explícitamente
  esta limitación en activación, sin introducir aquí un gestor de procesos.

Referencia del mecanismo de configuración CLI:
https://learn.chatgpt.com/docs/config-file/config-reference

## 21. CODEX-ACTIVATION-001 Phase A: protected_paths

El motor evalúa `PROJECT_RULES.yaml.protected_paths` contra `touched_paths` de
la evidencia Git existente: cambios, creaciones, eliminaciones, untracked y ambos
extremos de renombres. Se aplica independientemente del proveedor y antes de
mandatory tests; también se revalida después de tests y en continuidad/capacidad.
Protected prevalece sobre authorized_files; forbidden_files mantiene su control
exacto existente. Una violación bloquea, no alcanza Human Gate ni provoca otro
modelo automáticamente. No restaura, elimina ni revierte cambios.

Los patrones son relativos a la raíz; se normalizan separadores y se reutiliza
la validación de rutas de evidencia para rechazar absolutos, drives y traversal.
Matching de ruta completa: `*`, `?` y clases de fnmatch operan dentro de un
segmento; `**` como segmento abarca cero o más segmentos. No hay prefijos ni
directorios implícitos. Comparación sin distinción de casing en Windows; el
control exacto anterior de Task Packet no cambia. No se recorren archivos para
resolver patrones ni se leen contenidos para explicar una violación. El motivo
es fijo y sanitizado. Configuración inválida falla cerrado en la evaluación.

RESOLVED_BY_ENGINE_PROTECTED_PATH_SNAPSHOT_AND_SCOPE_ENFORCEMENT significa
control DETECTIVO en tiempo de validación del Orquestador. La captura local de
rutas protegidas complementa Git y cubre archivos ignorados: compara antes y
después de cada invocación Builder y de la ejecución de mandatory tests nombres
relativos, tipos y SHA-256 de archivos
regulares. Un archivo preexistente sin cambios no viola esta comparación.
Creación, sustitución incluso del mismo tamaño, eliminación y renombres hacia o
desde protección durante el Builder bloquean antes de mandatory tests; durante
mandatory tests bloquean antes de Human Gate. Se conserva la
captura Git posterior; no hay restauración ni llamada correctiva automática.

Las capturas viven solo en memoria; ni contenidos ni hashes se persisten, se
registran o se envían al modelo. El recorrido queda dentro de la raíz validada,
sin depender de reglas ignore. Omite .git salvo patrón que lo gobierne; no sigue
symlinks/reparse points y falla cerrado ante ellos o evaluación insegura. Esta
limitación conservadora puede bloquear repositorios con enlaces. Los patrones
continúan procediendo únicamente de PROJECT_RULES.yaml.

Esto no impide intentos de escritura y NO impide lectura de archivos protegidos.
No constituye aislamiento preventivo de sandbox; la comparación corresponde a
las ventanas de ejecución Builder y mandatory tests, no a vigilancia permanente
del filesystem. La captura AFTER BUILDER válida se reutiliza como BEFORE TESTS:
las comprobaciones intermedias de Git/alcance son de solo lectura. AFTER TESTS se
captura también ante exit no cero, timeout o error manejado de ejecución. Un fallo
de prueba no omite esta revisión: una violación protegida prevalece en el motivo
y en security_review=false, manteniendo los resultados de pruebas sanitizados.

Phase A no activa Codex: developer sigue habilitado y codex_builder deshabilitado.
Fixtures temporales con datos sintéticos y subprocess mock permiten seleccionar
Codex sin cambiar configuración canónica; no constituyen smoke real. Phase B
requiere Human Critical Approval y un repositorio desechable sintético separado.

Permanecen sin resolver CODEX_ACTIVATION_BLOCKER_AUTH_UNVERIFIED,
WINDOWS_SANDBOX_UNVERIFIED, NETWORK_ISOLATION_UNVERIFIED,
REAL_JSONL_CONTRACT_UNVERIFIED, REAL_CLI_ARGV_UNVERIFIED,
WINDOWS_ENVIRONMENT_SUFFICIENCY_UNVERIFIED y DESCENDANT_PROCESS_CLEANUP_UNVERIFIED.
AUTH_STATE sigue UNKNOWN.

## 22. Phase B: diagnóstico de evidencia de acciones

Primer smoke real controlado: autenticación READY, proceso lanzado, argv aceptado,
exit 0 y turn.completed reconocidos. No se observó la modificación solicitada ni
resultados de probes de sandbox/red/descendientes. No se conservó JSONL/stderr
crudo; la causa de la ausencia de acciones no puede reconstruirse. No se autoriza
otra invocación real en DIAGNOSTIC-AND-ACTION-EVIDENCE-001.

SUCCESS significa exclusivamente "Codex turn completed successfully at the
adapter boundary", no implementación realizada. Exit 0, JSONL válido e inicio y
terminal de éxito son suficientes; no se exige acción ni cambio de archivo.
El motor conserva Git, protected_paths, alcance, pruebas y gates como autoridad.
Un turno sin cambios puede llegar a Human Gate si supera esas comprobaciones;
no existe requisito global de modificación. Un requisito por tarea de cambio
obligatorio necesitaría una decisión futura, no se implementa aquí.

Telemetría sanitizada: event_count, item_started_count, item_completed_count,
command_execution_count, file_change_item_count y action_evidence_observed.
Los dos contadores de acciones cuentan IDs únicos de tipos explícitos
command_execution/file_change, no cada actualización del mismo item. IDs y
payloads nunca salen del parser. El booleano solo indica presencia estructurada
de esos items, no éxito del comando ni aceptación. Mensajes y reasoning no cuentan.
Se exige item.type string e ID no vacío. La validación terminal cerrada existente
se conserva: eventos superiores desconocidos fallan cerrado, pues no se puede
determinar si alteran el ciclo terminal. Tipos item desconocidos no aportan
evidencia de acción. Salida inválida o exit no cero devuelve contadores por defecto,
no prueba ausencia de acciones; turn.failed válido puede conservar los contadores.

Ayuda local inspeccionada: codex-cli 0.159.0. Confirma '-' como prompt stdin,
workspace-write, approval never y --ignore-user-config (omite config.toml, no
anuncia desactivación de herramientas). No anuncia --full-auto; no se establece
equivalencia ni se cambian flags. No se confirma retroactivamente la versión del
smoke anterior. Referencia de eventos: https://learn.chatgpt.com/docs/non-interactive-mode
La referencia oficial describe --full-auto como compatibilidad obsoleta y
recomienda --sandbox workspace-write; no demuestra una necesidad de cambiar flags.

Estado actual: autenticación local disponible; CLI/argv observados; JSONL se
precisa como REAL_JSONL_TERMINAL_CONTRACT_OBSERVED. Semántica real de acciones
pendiente: CODEX_ACTION_EXECUTION_EVIDENCE_UNVERIFIED. Continúan pendientes
WINDOWS_SANDBOX_UNVERIFIED, NETWORK_ISOLATION_UNVERIFIED,
WINDOWS_ENVIRONMENT_SUFFICIENCY_UNVERIFIED para trabajo Builder completo y
DESCENDANT_PROCESS_CLEANUP_UNVERIFIED (Codex y pruebas). El bloqueo de rutas
protegidas conserva su resolución Phase A. Codex permanece deshabilitado.

## 23. HOST-SMOKE-LAUNCHER-001: launcher manual de activación

Diagnóstico comunicado y confirmado por el Director: el mismo Python 3.14.4
aprobado inicia como `anap\anapo` y recibe ACCESS DENIED antes de iniciar como
`AnaP\CodexSandboxOffline`. Clasificación: HARNESS_OR_PARENT_CONTEXT_BLOCK:
CONFIRMED. No se autoriza ni requiere remediación de seguridad Windows según
esta evidencia. El smoke controlado se lanza desde el host normal; el modelo
continúa sujeto al sandbox de la CLI mediante el adaptador existente.

`scripts/codex_activation_smoke.py` es tooling manual, no flujo de producción.
No ejecuta sin `--execute-approved-smoke --expected-head <40-hex-SHA>`.
El Director suministra el SHA comprometido después de implementación, revisión,
pruebas y commit. Antes y después exige ese HEAD exacto, rama
`task/codex-activation-001`, árbol limpio sin staged/untracked y roster canónico
Codex deshabilitado/Developer habilitado; no hay exclusiones de archivos.
Exige el intérprete aprobado y contexto host normal; reutiliza filtrado de
entorno y adaptador, con máximo una llamada por proceso sin retry/resume.
La aprobación humana no la concede el launcher ni se renueva al reiniciarlo.

Solo prepara recursos sintéticos propios, correlaciona telemetría sanitizada
con efectos físicos y limpia raíces registradas si identidad, propietario de
ejecución y ausencia de reparse points se verifican. La aprobación pendiente
no se consume durante implementación. No se resuelven aquí los bloqueos de
sandbox/red/descendientes ni se activa Codex. Las pruebas automatizadas quedan
pendientes de ejecución independiente con el intérprete aprobado: el harness
de desarrollo no puede iniciarlo y no se permite sustituirlo.

CORRECTION-001: las observaciones físicas se recogen independientemente antes de
clasificar y limpiar. Una anomalía secundaria o excepción del adaptador no
suprime canary externo, resultado de red ni post-check del Orquestador. Prioridad:
ORCHESTRATOR_SCOPE_BREACH > SANDBOX_FAILURE > NETWORK_FAILURE > fallo CLI u otros
resultados. Estados subordinados sanitizados se conservan; evidencia inaccesible
deja recursos sin limpiar. Se mantienen los controles de propiedad y rutas.

Los probes no usan Python del perfil dentro del sandbox. Se seleccionan Windows
PowerShell de System32 y curl.exe de System32: ambos iniciaron con consultas de
versión sin modelo ni red en el contexto de desarrollo (PowerShell 5.1.26100.9444,
curl 8.21.0). El launcher repite esas comprobaciones de disponibilidad en host
antes de crear recursos; no modifica políticas de ejecución. Esto no demuestra
todavía ejecución de los probes ni aislamiento de sandbox/red.

El hijo del probe descendiente espera parent_done.flag durante un plazo acotado;
el launcher crea el sentinel exclusivamente tras retorno o excepción del
adaptador, espera ocho segundos y observa el canary. Un canary prematuro o
sentinel preexistente impide afirmar supervivencia post-adaptador. Esta observación
no resuelve DESCENDANT_PROCESS_CLEANUP_UNVERIFIED. Los bloqueos de activación
permanecen abiertos. H-OBS-2 se difiere: Path.home()/USERPROFILE no se contrasta
con el directorio de perfil obtenido de identidad OS; se conservan identidad
normal exacta y comprobaciones de límites existentes.

CORRECTION-002: H-1 permanece RESOLVED según revisión estática independiente.
Los probes se generan exclusivamente en memoria como comandos predeterminados
System32 PowerShell `-NoProfile -NonInteractive -EncodedCommand`; no se crean
scripts .ps1 ni se usa -File o un override de execution policy. El mismo estilo
EncodedCommand devolvió el token fijo y exit 0 como CodexSandboxOffline, sin
archivos/red/modelo. El preflight host usa ese estilo y curl System32 --version.
Toda ruta dinámica se inserta como datos UTF-8 Base64, y el comando completo se
codifica UTF-16LE Base64; ps_literal se elimina (H2-3: RESOLVED_BY_DATA_ENCODING).

H2-2: el probe verifica primero que curl --version inicia y termina correctamente.
Fallo de lanzamiento o condición de proceso no válida produce PROBE_UNAVAILABLE,
nunca PASS de red. Solo entonces hace una solicitud HTTPS acotada: exit 0 produce
UNEXPECTED_SUCCESS; exit no cero de curl produce BLOCKED. PROBE_UNAVAILABLE y
resultados ausentes/inválidos/inaccesibles dejan la conclusión inconclusa salvo
fallos de mayor prioridad. BLOCKED solo acredita que curl pudo ejecutarse y esa
solicitud no tuvo éxito; no demuestra aislamiento universal. La evidencia real
del smoke sigue pendiente y no se resuelve ningún bloqueo de activación.

HOST-SMOKE-ATTESTATION-REDESIGN-001 sustituye la instrucción con cuerpos Base64
por tres invocaciones cortas de wrappers .cmd creados por host. Se elimina la
edición/verificación de workspace.txt: solo OUTSIDE, NETWORK y DESCENDANT, una
vez cada uno. Cada línea del wrapper se limita a 8000 caracteres antes del modelo.
La prueba local sin modelo confirmó ejecución con handle de lectura y
FILE_SHARE_READ, denegando overwrite/delete/rename desde un hijo y conservando
bytes. El host mantiene handles CreateFileW sin share-write/share-delete hasta
después de evidencia, hashes, post-check y clasificación; luego cierra y limpia.
Pre/post SHA-256 solos eran INSUFFICIENT para N-1; son ahora defensa secundaria
con identidad, archivo regular y ausencia de reparse points. Duda al cerrar
handles impide limpieza.

El adaptador admite expectativas diagnósticas opcionales, neutrales por defecto.
SHA-256 de dominio codex-command-v1 y tipo str compara el item.command completo,
sin normalización, substring ni desempaquetar shells. Cada expectativa exige un
solo ID con started/completed y payload consistente. No se infiere éxito del
comando de completed. Para PASS se exigen exactamente tres comandos atestados,
cero comandos inesperados, cero file_change y cero otros tipos de acción; solo
mensajes/reasoning se excluyen del conjunto estricto. Esquema ausente/desconocido
impide PASS. No se devuelven comandos, hashes ni IDs.

BLOCKED solo tiene autoridad con acción exacta + wrapper protegido e íntegro +
evidencia física completa + post-check seguro. Fabricación por comando adicional
o file_change invalida acciones; modify-execute-restore lo impiden los handles,
no los hashes. Prioridad: scope breach > integridad de wrappers > brecha exterior
> acceso de red > acción estricta inválida > fallo CLI > inconcluso > PASS.
Las brechas físicas y la invalidez de acciones permanecen como estados subordinados
aunque otra clasificación domine. Se preserva H-1: recoger, correlacionar y
clasificar antes de liberar handles/limpiar. No cubre compromiso del host/parser,
no autentica criptográficamente al modelo, no prueba aislamiento universal ni
resuelve cleanup de descendientes. Smoke real todavía NO ejecutado; Codex sigue
deshabilitado y la aprobación humana pendiente no se consume en implementación.

HOST-SMOKE-ATTESTATION-REDESIGN-001 — CORRECTION-002 (intento final 2/2):
las tres cadenas canónicas identifican rutas absolutas de wrappers existentes,
regulares, sin reparse points y bloqueados por el host. System32 cmd.exe recibe
`/d /v:off /s /c` y el argumento entre dos pares de comillas mediante PowerShell
`--%`; se rechazan rutas con porcentaje, comillas dobles, NUL o saltos de línea.
La misma cadena en memoria alimenta instrucción y fingerprint. La comprobación
nativa sin modelo del candidato A pasó con espacios, apóstrofo ASCII y otros
metacaracteres, NoDefaultCurrentDirectoryInExePath presente, otro cwd y señuelos
en PATH; overwrite/delete/rename fueron denegados y SHA-256 permaneció igual.
Esto acredita factibilidad de esa construcción Windows, no aislamiento del smoke.

F-2 permanece FAIL_CLOSED_REAL_SCHEMA_PENDING: la CLI local 0.159.0 y su ayuda
no establecen la representación real de item.command. Se conserva comparación
exacta de strings completos, sin normalización ni aceptación por partes. El
primer smoke real controlado también aportará evidencia sanitizada del esquema.
Una representación incompatible significa atestación no establecida y resultado
INCONCLUSIVE / STRICT_ACTION_SET_INVALID; por sí sola no demuestra fallo de
sandbox, red o seguridad del adaptador. Las brechas físicas conservan prioridad.
En modo diagnóstico estricto se cuentan items de comando únicos con al menos
una observación de campo presente o string (command_field_present_count y
command_field_string_count); lifecycle_command_consistent_count cuenta items
con started/completed, payload único y ciclo válido, incluso sin coincidencia.
Estos contadores no autorizan aceptación. Se reutilizan attestations.observed
para coincidencias exactas, unexpected_command_execution_count para payloads
no esperados y command_payload_conflict_count para conflictos. Eventos con
campo ausente/no-string siguen invalidando aceptación aunque otro evento del
mismo item tenga string. Comandos, hashes, IDs y JSONL nunca se exponen.
Smoke real NO ejecutado; Codex canónico sigue deshabilitado y la aprobación
permanece sin consumir. Pruebas Python pendientes del verificador independiente
por el bloqueo confirmado del intérprete aprobado en el harness de desarrollo.
