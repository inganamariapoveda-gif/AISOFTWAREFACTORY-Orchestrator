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

**D3 — CONTROLLED TASK-BRANCH PUBLICATION.** La Product Owner aprobó esta
ampliación mediante HUMAN_BUSINESS_DECISION (GIT-PUBLISH-GOVERNANCE-001).
Publicación controlada de ramas de tarea dentro del MVP como AMARILLO
CONTEMPLADO; push no controlado, merge y producción permanecen prohibidos.
Contrato declarativo en §25; ejecución operacional todavía no implementada.

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
9. Confirmar el cambio en una **rama de tarea** y cerrar la tarea. Publicación controlada opcional bajo §25; sin merge ni producción.
10. Persistir toda la traza en SQLite de forma reconstruible.

Todo esto en ejecución **local**, un proceso, un operador.

---

## 4. Fuera de alcance (deliberado)

Dashboard avanzado · SaaS · multiusuario · marketplace de agentes · multiagente avanzado · facturación · infraestructura distribuida (Kubernetes, Docker, colas, Redis, servidores) · despliegue automático a producción · aplicación móvil · sistema complejo de notificaciones (aprobaciones entrantes, bot interactivo, botones, múltiples canales, motor de mensajería; el **aviso saliente simple** de un Human Gate SÍ está dentro del MVP, §3.8 y §9) · integraciones empresariales no necesarias para demostrar el ciclo · `git push` no controlado, `git merge` y cualquier operación sobre producción · eliminaciones irreversibles · gestión de credenciales de terceros.

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
| `READY_FOR_COMMIT` | Motor confirma en rama de tarea (sin publicación automática; nunca merge ni producción; publicación controlada separada en §25) | `COMPLETED` |
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
| `PROJECT_RULES.yaml` (por proyecto) | Ruta del repositorio, comandos como DATA, rutas protegidas; autonomy_overrides debe ser {} mientras no exista semántica implementada (§28). |

Regla de composición: al **agregar un proyecto** solo se añade su `PROJECT_RULES.yaml`; el núcleo del motor no se modifica. Los cambios de governance/config requieren Mutation Boundary explícito y la aprobación aplicable; la admisión por sí misma no impide mutaciones de archivos.

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
| Tests | resolución de `pruebas_obligatorias` / comandos de `PROJECT_RULES.yaml` como DATA; ejecución local prohibida, backend aislado requerido (§26) |
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

Un solo proceso Python para el motor local, patrón **puertos y adaptadores** para desacoplar proveedores. Sin microservicios. El código candidate y los comandos del proyecto requieren un backend aislado: su ejecución local está prohibida (§26).

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
- `verifier/runner` — resuelve pruebas como datos y conserva el contrato de evidencia (§11). La ejecución de candidate requiere backend aislado; mientras no esté integrado, mandatory_tests no vacíos bloquean antes del Builder (§26).
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
- La configuración de AIP vive en `PROJECT_RULES.yaml`: `repo_path`, comandos como DATA, rutas protegidas y autonomy_overrides obligatoriamente {} (§28).
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
8. Confirma en rama de tarea (sin merge ni producción) y cierra en `COMPLETED`; publicación controlada únicamente bajo §25.
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
| Acción irreversible o de producción | Clasificación ROJO + prohibición en MVP; commit solo en rama; publicación controlada bajo §25, sin merge. |
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
la capability de implementación no concede por sí sola Git, comandos de tests/build al modelo, administración de bases de
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
Se copian valores presentes, conservando casing; en Windows se añade únicamente
SYSTEMDRIVE derivado del drive válido de SYSTEMROOT, nunca del SYSTEMDRIVE ambiente.
SYSTEMROOT ausente, relativo, UNC, de dispositivo o inválido falla cerrado.
No se heredan variables
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
consumo tras resultado incierto, evidencia y Human Gates. Los mandatory tests
no vacíos bloquean antes del Builder hasta integrar el backend aislado (§26). El
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

Estado transitorio (§26): los controles PRE/POST TEST descritos aquí se conservan
como contrato de reporting/review y se cubren con resultados sintéticos. No
implican ejecución operacional local: mandatory_tests no vacíos bloquean antes
del Builder mientras no exista un backend aislado autorizado.

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

CODEX-EXECUTABLE-BINDING-001: la configuración conserva `executable: codex` y
su validación cerrada. El launcher resuelve una sola vez desde PATH filtrado;
si no encuentra candidato, en Windows inspecciona únicamente
`<USERPROFILE>/AppData/Local/OpenAI/Codex/bin/<hijo-directo>/codex.exe`.
USERPROFILE procede del entorno filtrado existente; no se amplía PATH ni su
allowlist. No se fija versión ni directorio hash. Cero candidatos falla cerrado;
más de uno produce CODEX_EXECUTABLE_AMBIGUOUS, sin elegir por orden o fecha.
Se exige ruta absoluta, archivo regular codex.exe, sin traversal ni reparse
points en archivo/ancestros y, para discovery, relación directa con bin.
Un candidato inseguro o error de inspección detiene la selección.
No se pretende discovery universal: esta estructura Windows es la soportada.

La misma ruta validada alimenta los tres preflights y el argumento opcional
`resolved_executable` del adaptador. Con binding no hay segunda búsqueda ni
fallback; el adaptador comprueba ruta absoluta, archivo regular y ausencia de
links/reparse points antes de ejecutar exactamente la ruta recibida. Sin binding
conserva su comportamiento anterior. Este binding identifica una ruta; no añade
un lock del ejecutable ni una política de firmas. La procedencia del discovery
corresponde al launcher. Solo se reporta FILTERED_PATH,
BOUNDED_WINDOWS_INSTALLATION, FAILED o AMBIGUOUS; nunca ruta ni lista de candidatos.
Los controles del smoke y el límite de una llamada no cambian. No se efectuó
ninguna llamada real durante esta implementación; aprobación sin consumir y
Codex canónico deshabilitado. Pruebas pendientes de verificación independiente.

CODEX-WINDOWS-SANDBOX-BACKEND-001, actualizado por la decisión aprobada
CODEX-WINDOWS-ELEVATED-BACKEND-001: el adaptador vincula explícitamente
`windows.sandbox="elevated"` mediante un único override
global antes de `exec`, exclusivamente cuando el runtime es Windows nativo.
El esquema cerrado actual no tiene campo de backend: se implementa como binding
de compatibilidad de plataforma, sin ampliar configuración ni opciones de política.
`--ignore-user-config` sigue siendo obligatorio junto con workspace-write,
approval never y el filtro de entorno existente (incluido SYSTEMROOT). No se
añade --ignore-rules ni fallback automático a unelevated, danger-full-access,
ejecución sin sandbox o configuración de usuario, ni un segundo intento automático.
Sin Windows no se añade selector. La identidad del ejecutable permanece única.
Las restricciones de red y la telemetría/atestación estrictas permanecen intactas.

Antes de consumir una llamada real, el launcher usa el mismo ejecutable y selector
en un control sin modelo: `sandbox -P :workspace -C <workspace-propio>` ejecuta
únicamente System32 cmd con echo de un token fijo. Exige exit 0 y salida exacta;
timeout o fallo impide invocar al modelo. El workspace nuevo se registra con las
reglas de propiedad existentes y se limpia en el finally habitual o queda
preservado si no puede limpiarse con seguridad. No se tocan recursos forenses
anteriores. Único nuevo dato público: windows_sandbox_backend_preflight con
NOT_RUN/PASS/FAIL/NOT_APPLICABLE, sin comandos, rutas ni salidas crudas.

Este preflight acredita solamente aceptación del backend y ejecución local de
un proceso inocuo; no demuestra disponibilidad/selección de herramientas en exec,
esquema JSONL, aislamiento universal de red ni éxito del smoke. La evidencia host
sin modelo del backend explícito y de la cadena de shell fue PASS, según el
Task Packet; la ayuda local acepta la colocación sintáctica del override.
No está probado que la omisión anterior del backend causara el smoke inconcluso.
La aprobación real previa está CONSUMED 1/1, restantes 0. No se efectuó inferencia
en esta implementación; cualquier retry real requiere NUEVO Human Critical
Approval. Codex canónico sigue deshabilitado.

SMOKE-CLEANUP-OBSERVABILITY-001: `cleanup` conserva sus valores existentes
NOT_NEEDED, COMPLETE y CLEANUP_INCOMPLETE. Se añade únicamente `cleanup_detail`,
con enum cerrado: NOT_RUN, COMPLETE, EXPECTED_SAFE_PRESERVATION,
HANDLE_RELEASE_FAILURE, OWNERSHIP_VALIDATION_FAILURE, RESOURCE_IDENTITY_MISMATCH,
CLEANUP_SAFETY_CHECK_FAILURE, DELETE_ACCESS_DENIED, DELETE_OTHER_FAILURE, UNKNOWN.
UNKNOWN queda reservado; las fases actuales siempre tienen una categoría fija.
La clasificación es diagnóstica: no cambia elegibilidad, ownership, tokens,
identidad, links, hard links, reglas .git, orden, protección/liberación de handles,
evidence_complete, preservación ni comportamiento de shutil.rmtree.
No expone rutas, nombres temporales, tokens, hashes, identidades, números Windows,
excepciones, stderr, usuarios ni valores de entorno.

Precedencia: HANDLE_RELEASE_FAILURE > RESOURCE_IDENTITY_MISMATCH >
OWNERSHIP_VALIDATION_FAILURE > CLEANUP_SAFETY_CHECK_FAILURE > DELETE_ACCESS_DENIED >
DELETE_OTHER_FAILURE > EXPECTED_SAFE_PRESERVATION > COMPLETE. El fallo de cierre
impide intentar limpieza; evidencia incompleta preserva tras liberar handles.
Entre raíces se conserva la categoría de fallo de mayor precedencia y se sigue
intentando cada raíz en el orden previo, sin rollback de eliminaciones exitosas.
PermissionError durante rmtree indica DELETE_ACCESS_DENIED; otras excepciones
de borrado indican DELETE_OTHER_FAILURE. Fallos anteriores se clasifican por
la comprobación activa. Una raíz ya ausente sigue produciendo incompleto con
CLEANUP_SAFETY_CHECK_FAILURE: no se transforma en éxito ni se presume su causa.

La causa histórica de CLEANUP_INCOMPLETE permanece UNKNOWN; el candidato con
marcador de formato válido NO fue probado como perteneciente a aquella ejecución.
La nueva evidencia permitirá distinguir clases de fallo en un smoke futuro,
sin reconstruir la causa histórica. Aprobación previa CONSUMED 1/1, restantes 0;
cualquier llamada real futura requiere NUEVO Human Critical Approval.

## 24. SAFE-TEST-RUNNER-001

IMPLEMENTATION-001 — TRUSTED RUNNER CAGE FOUNDATION construye únicamente
el contrato estático en `.github/workflows/safe-test-runner.yml` y sus tests de
texto en `tests/test_safe_test_runner_contract.py` (biblioteca estándar).
Estado vigente tras IMAGE-ADMISSION-001:
**STATICALLY ADMITTED / EXECUTION INTENTIONALLY DISABLED**. No autoriza ejecutar
Docker, Actions, tests ni código candidato durante esta implementación.
No integra el runner con el Orquestador, adaptadores, CLI ni Integrity Gate.

**Threat model y confianza.** El candidate puede contener código, tests,
configuración y salida deliberadamente hostiles. El workflow confiable de
`main` es el control plane; el checkout del candidate es un untrusted payload.
El candidate nunca determina workflow, imagen, argumentos Docker, comandos,
permisos, secretos, mounts, red, límites ni test target. El host no ejecuta
scripts, hooks, setup, Dockerfiles ni actions locales del candidate. Los
programas de control y el parser de salida se definen inline en el workflow
confiable; no se cargan del checkout. Un candidate que falsifica el resultado
no debe poder debilitar el aislamiento del host ni la protección de datos.

**Regla operacional futura.** Trusted workflow must be dispatched from main:
el Orquestador futuro deberá invocar `workflow_dispatch` con **`ref=main`**
explícito. No se implementa ese despacho aquí. El único evento permitido es
`workflow_dispatch`; su único input obligatorio es `candidate_sha`. El primer
control exige `github.ref == refs/heads/main` y falla inmediatamente en otro
ref. Esta comprobación depende de usar realmente el workflow confiable: una
copia modificada en otra rama podría eliminar su propio guard; por ello el
despachador futuro debe cumplir la regla, no confiar en workflows del candidate.

El SHA se recibe como dato de entorno, sin interpolación directa en shell,
y se valida con `^[0-9a-f]{40}$` antes de exportarlo al checkout. No admite
branches, tags, HEAD, abreviaturas, reflogs ni expresiones rev. Se usa únicamente
el repositorio actual, ref exacto validado, path fijo `candidate`, profundidad 1,
sin submodules ni LFS y con `persist-credentials: false`. La única action es
`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1).
No hay otras actions, instalación de paquetes ni nuevas dependencias.

**IMAGE-ADMISSION-001 — IMAGE ADMISSION STATUS: STATICALLY ADMITTED.**
Única referencia aprobada expresamente por el Director:
`docker.io/library/python@sha256:a66d3a463d0be3cc537c269b0d3418746dda512417a975559a0eaa8a6406baaf`.
Upstream: Python 3.14.8 slim-bookworm. Platform: `linux/amd64`.
Provenance declarada por el Task Packet: Docker Official Image / library/python.
Pin por manifest digest específico linux/amd64, sin tags ni referencia a un
índice mutable. No se consultó red, resolvió digest ni inspeccionó una imagen
real en esta tarea; se implementó el contrato exacto autorizado.

Las constantes confiables SAFE_TEST_IMAGE, SAFE_TEST_PLATFORM y
SAFE_TEST_PYTHON_VERSION deben igualar exactamente la referencia anterior,
`linux/amd64` y `3.14.8`. No basta formato sha256 válido: registry, repository,
digest, platform o versión diferentes fallan. No hay fallback ni inputs para
estos valores. El gate separado `SAFE_TEST_EXECUTION_ENABLED=false` falla
antes de publicar outputs y antes de checkout, pull o run.
**IMAGE ADMITTED != EXECUTION ENABLED.** Habilitar requiere otra tarea explícita
y nueva revisión; esta admisión no equivale a technical approval.

El camino futuro, todavía deshabilitado, es preflight confiable → docker pull
con platform exacta → docker image inspect → candidate checkout → contained run.
El candidate aún no existe durante preparación e inspección y no participa en
admisión. Pull usa exclusivamente la referencia aprobada y `linux/amd64`, sin
login, credenciales de registry, retries ni instalación. Fallo de pull detiene.

Metadata esperada: Os linux, Architecture amd64, Config.Entrypoint null o lista
vacía, Config.Cmd exactamente ["python3"], Config.User y Config.WorkingDir strings
vacíos, Config.Volumes null o mapa vacío. Config.Healthcheck debe ser null o
ausente: se lee como JSON con `index .Config "Healthcheck"`, cuyo resultado
para clave ausente es null; cualquier objeto declarado, incluso vacío, falla.
Fallo de inspect/representación o mismatch detiene antes del checkout, sin
ejecutar la imagen. No se amplía la inspección a otros campos.
**VOLUME declarado forbidden** y
**ENTRYPOINT no vacío forbidden**: cualquier diferencia falla, aunque run
sobrescriba CMD/ENTRYPOINT. USER y workdir de ejecución siguen forzados a
`65534:65534` y `/candidate`. Campos ausentes/indeterminados o inspect fallido
no habilitan checkout. Se inspeccionan campos en formatos JSON para comparar
valores y tipos; no se ejecuta la imagen para esta inspección.

Config.Env debe incluir exactamente una entrada `PYTHON_VERSION=3.14.8`.
Se rechazan entradas malformadas y nombres credential-like, sin distinguir
mayúsculas: GITHUB_*, ACTIONS_*, AWS_*, AZURE_*, GOOGLE_*, SSH_*, DOCKER_AUTH_CONFIG
y nombres que incluyan TOKEN, SECRET, PASSWORD, CREDENTIAL, API_KEY o PRIVATE_KEY.
No se exige igualdad del conjunto completo de ENV ni se imprimen sus valores.
La metadata se trata exclusivamente como datos. El futuro run usa la misma
SAFE_TEST_IMAGE, `--platform linux/amd64` y `--pull never`, sin Dockerfile/build.
La capacidad efectiva con UID/GID no root y sin red sigue pendiente de validación
en una ejecución futura autorizada; no se demuestra con metadata ni narrativa.
Digest pinning no implica ausencia de vulnerabilidades ni aislamiento perfecto.

**Protección del host y de los datos.** WORKTREE != SECURITY ISOLATION.
Los trabajos de contención se desarrollan en clones Git independientes y/o
runners descartables. Un clon independiente separa metadata Git, pero tampoco
es una frontera para ejecutar código hostil en el computador de la usuaria.
La arquitectura futura es GitHub-hosted ephemeral VM (`ubuntu-24.04`) →
workflow confiable de main → candidate por SHA → container Docker contenido.
No usa runners propios. No monta home, SSH, almacenes de credenciales, socket
Docker, raíz del host, `/github`, `/home/runner`, workspace completo ni archivos
del control plane. El único contenido de repositorio montado es el candidate.

**Credential boundary.** Permisos explícitos únicamente `contents: read`;
resto sin concesión. Sin environments ni expresiones de secrets. El token de
checkout no se persiste en Git ni se pasa al container. No se heredan variables
de entorno del host, runtime tokens, cloud tokens, claves SSH ni credenciales
Git. La única variable pasada explícitamente a Docker es
`PYTHONDONTWRITEBYTECODE=1`; el entorno interno de la imagen debe revisarse
en IMAGE-ADMISSION. La salida cruda del candidate no se publica en logs ni se
evalúa como shell o comandos de Actions.

**Network model.** La fase confiable de preparación de la VM puede usar red
para checkout y para obtener una imagen previamente admitida. La fase de
ejecución no confiable usa `--network none` en el CONTAINER; no se afirma que
toda la VM esté aislada de red. El run usa `--pull never` después del pull
confiable, sin resolver imágenes desde datos del candidate.

**Filesystem y containment.** Root filesystem `--read-only`; bind de
`${GITHUB_WORKSPACE}/candidate` a `/candidate` readonly; working directory
`/candidate`. Se solicitan tmpfs temporales explícitos en `/tmp`, de
128 MiB, y `/dev/shm`, de 16 MiB, ambos con noexec/nosuid/nodev y mode=1777.
Usuario numérico `65534:65534`,
`--cap-drop ALL`, `--security-opt no-new-privileges`, sin modo privilegiado,
devices ni namespaces host de network/PID/IPC. No se permite escribir al
candidate ni al repositorio del host. Los límites son 2 CPU, 1 GiB de RAM
(memory-swap igual a RAM), 128 PIDs y job de 15 minutos. La invocación Docker
tiene además timeout de 10 minutos; timeout o exit no cero falla, sin retries.
`--init` atiende señales y recolección de procesos dentro del container.
El nombre fijo `safe-test-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}` depende solo
de valores GitHub confiables. El trap EXIT guarda primero el exit code original,
desactiva su propio trap, neutraliza nuevas INT/TERM con `trap '' INT TERM`
antes de las operaciones Docker e intenta `docker rm --force` del nombre esperado.
Después consulta `docker container ls --all` con filtro exacto del nombre:
solo una consulta exitosa sin resultados acredita ausencia. Container presente,
consulta fallida/timeout o fallo al eliminar el archivo de salida hace fallar
cleanup. Cada operación Docker de cleanup tiene timeout de 10 segundos y
kill-after de 5 segundos. Si la ejecución original falló, se conserva su código;
si tuvo exit 0 pero cleanup falló, el resultado es FAIL. No se convierte fallo
en PASS. `--rm` complementa el cleanup. Cancelación abrupta/SIGKILL o pérdida
de la VM no garantiza que termine el trap; sigue siendo necesaria la VM
descartable. Todo volumen declarado se rechaza en la inspección previa al checkout.

**Suite crítica futura y señal no verificada.** El comando fijo preparado es
`python -B -m unittest tests.test_integrity_gate -v`, exclusivamente dentro
del container; se anula el entrypoint de la imagen. La señal provisional exige exit
code 0, exactamente 71 tests, failures=0, errors=0 y skips=0. El parser de
texto confiable exige 71 líneas de éxito, un único resumen de 71 tests y un
único `OK`, y rechaza skips, failures, errors, expected failures y unexpected
successes. Salida ausente o inconsistente falla cerrado. Esta comprobación
protege contra skips accidentales, **NO es prueba criptográfica frente a tests
deliberadamente hostiles** que pueden falsificar texto. El aislamiento de host
y datos no depende de confiar en unittest. El resumen lleva obligatoriamente
la etiqueta `candidate-reported test summary (UNVERIFIED)` y la advertencia
`contract/result signal only: NO technical approval; NO security approval`.
No acredita ejecución real de 71 tests ni aprobación técnica o de seguridad;
no se introduce un sistema de evidencia confiable en esta corrección. Los logs
propios contienen solo ref fuente, SHA validado, runner OS, settings no sensibles,
exit code y señal no verificada; nunca entorno completo, tokens, headers o Git
config. El output se captura fuera del bind, no se publica ni se sube como artifact.

**CORRECTION-001 — cuota de salida no confiable.** `--log-driver none` evita
almacenamiento duplicado por el daemon Docker. El archivo temporal conjunto de
stdout/stderr del cliente tiene cota de **1 MiB (1.048.576 bytes)** mediante
`prlimit --fsize` con límites soft y hard iguales, heredados por timeout y el
cliente Docker. No depende de unidades implícitas de ulimit ni de pipelines.
Un exceso provoca error de escritura/señal; se captura inmediatamente el exit
code de la invocación y se conserva cualquier fallo. Incluso si el cliente
ignora el error y retorna 0, `stat` debe demostrar tamaño estrictamente menor
que la cuota antes del parser. Alcanzar exactamente la cuota también falla:
no se acepta truncamiento silencioso. Error de medición o tamaño inválido falla
cerrado. El shell principal y su cleanup quedan fuera de prlimit; el trap se
ejecuta en rutas normales de fallo y elimina el archivo temporal. Esta cuota
limita ese archivo, no todo I/O del host ni el buffer interno del daemon.

**CORRECTION-001 — regresión de expresiones.** Los tests estáticos inspeccionan
todos los valores `run:` del formato de mappings por indentación del workflow,
incluidos valores inline/folded, y rechazan cualquier `${{ ... }}` dentro de
ellos, sin depender del contexto de la expresión. Incluyen casos negativos
para github.event.inputs.candidate_sha, github.token y env.MALICIOUS, además
de inputs y secrets. Los mappings env/with adyacentes quedan fuera de esos
valores; sus expresiones conservan el diseño aprobado. No es un parser YAML
general. También se comprueba mediante mutación que omitir el nombre del
container viola el contrato. Ningún test se ejecuta en CORRECTION-001.

**Límites y revisión pendiente.** Un container no equivale a una VM: comparte
kernel con el runner. La VM hospedada por GitHub es la frontera adicional de
protección del computador de la usuaria; un container escape sigue siendo
riesgo residual. Por eso el job no tiene secrets, usa token mínimo read-only
y nunca entrega ese token al candidate. Docker no es aislamiento perfecto.
Los límites de CPU/RAM/PIDs/tmpfs y del archivo de salida no constituyen una
cuota integral de I/O o de logs del host. Los tests estáticos son regresiones de contrato,
no un parser general YAML/shell ni una demostración de aislamiento efectivo.
En este incremento no se ejecutan: quedan para revisión independiente; no se
declara TECH_APPROVED ni se habilita ejecución por haber escrito esta foundation.

**CORRECTION-002 — cierre estático de N-01, N-02, G-01 y G-02.**

N-01: RESOLVED mediante allowlist global de expresiones literales y sus
multiplicidades. Se inspecciona TODO el texto, independientemente de la sintaxis
YAML de run:. Únicamente se permiten las siguientes expresiones exactas:

| Expresión | Ocurrencias |
|---|---:|
| `${{ github.ref }}` | 1 |
| `${{ inputs.candidate_sha }}` | 1 |
| `${{ steps.preflight.outputs.image }}` | 2 |
| `${{ steps.preflight.outputs.platform }}` | 1 |
| `${{ steps.preflight.outputs.python_version }}` | 1 |
| `${{ steps.preflight.outputs.candidate_sha }}` | 1 |

Una expresión nueva, reemplazada, duplicada, ausente o sin cierre falla el
contrato. Las mutaciones cubren posiciones distintas, run con espacio antes
de dos puntos, lista con espacios adicionales y flow mapping, incluyendo
github.token, github.event.inputs.candidate_sha, secrets.X, vars.X,
env.MALICIOUS e inputs.command. El detector previo de run se mantiene solo
como defensa adicional; el rechazo de expresiones no reconocidas ya no depende
de reconocer todas las formas de run. No se añade parser YAML ni dependencia;
la allowlist no constituye validación semántica general de YAML.

N-02: RESOLVED para nuevas INT/TERM normales durante cleanup tras neutralizar
esas señales al entrar. Se conserva original_exit, EXIT desarmado, eliminación
y verificación posterior del container y propagación de fallos. SIGKILL y
pérdida de VM siguen sin permitir garantía de cleanup.

G-01: bloques literales completos fijan las nueve asignaciones inspect con
disyunción de fallos, el predicado completo de mismatch y el contrato ENV:
OS/Architecture, Entrypoint, Cmd, User, WorkingDir, Volumes, Healthcheck,
formato ENV, rechazo credential-like, valor PYTHON_VERSION y conteo único.
Mutaciones de cada `||` a `&&`, de conjunciones internas a disyunciones,
comparadores, conteo y salidas de fallo deben ser rechazadas. Las expectativas
son constantes de los tests, no se derivan del workflow al ejecutar tests.

G-02: Healthcheck declarado prohibido, incluso objeto vacío; se admite solo
null/ausente. Inspección y rechazo ocurren antes del candidate checkout.
Este cierre es de implementación estática pendiente de revisión independiente:
tests NOT RUN, ejecución DISABLED; no equivale a TECH_APPROVED.

Se mantienen Docker != VM, candidate output = UNTRUSTED,
functional signal = UNVERIFIED y WORKTREE != SECURITY ISOLATION.

## 25. GIT-PUBLISH-GOVERNANCE-001 — CONTROLLED TASK-BRANCH PUBLICATION

IMPLEMENTATION-001 / SCOPE-CORRECTION-001 registra la decisión material aprobada
por la Product Owner mediante HUMAN_BUSINESS_DECISION: git push se deniega por
defecto, con una única operación contemplada `git_publish_task_branch`.
Es AMARILLO CONTEMPLADO y requiere autorización explícita del Director mediante
DIRECTOR_INTERNAL_GATE. No requiere nuevo Human Gate para cada publicación que
cumpla exactamente el contrato; una desviación material sigue BLOCKED →
HUMAN_BUSINESS_DECISION. Merge y producción continúan absolutamente prohibidos.

MOTOR != REGLAS. POLICIES declara uncontrolled_git_push prohibido y la única
controlled_action con enabled=true, classification=AMARILLO,
approval=DIRECTOR_INTERNAL_GATE y on_violation=BLOCKED. PERMISSIONS mantiene
denegaciones de producción, merge, irreversibles, env_files y secret_files,
y sustituye la denegación absoluta de push por uncontrolled_git_push=true.
Los bloques antiguos se rechazan, también si coexisten con los nuevos: no hay
compatibilidad silenciosa ni defaults permisivos. Las claves desconocidas o
faltantes de los nuevos mappings cerrados causan ConfigError.

La política canónica git_publish exige enabled=true, remote_name=origin,
allowed_remote_urls con una única URL exacta:
`https://github.com/inganamariapoveda-gif/AISOFTWAREFACTORY-Orchestrator.git`.
Comparación futura exacta, sin normalización a URL equivalente, wildcard,
URL SSH alternativa ni otro repository. branch_prefix=task/, forbidden_branches
incluye main y master, refspec_mode=current_branch_only. Se prohíben force,
tags y eliminación remota. Se exige Task Packet explícito, aprobación del
Director y working tree limpio. La política no contiene comandos shell.

Builder admite únicamente implement_authorized_changes y
publish_authorized_task_branch. Director y Verifier carecen de capabilities
operacionales. Una capability sola nunca autoriza publicación. Deben coincidir
simultáneamente capability, controlled_action habilitada, git_publish habilitado,
Task Packet, aprobación del Director, gate y restricciones Git verificadas.
Falta, error o ambigüedad en cualquiera significa DENY/BLOCKED. GATES conserva
los Human Gates y exige amarillo_contemplado=true y git_publish_task_branch=true
dentro del gate interno del Director.

El loader solo valida estructura declarativa: booleanos reales, flags de riesgo
siempre false, requisitos de autorización siempre true, URLs HTTPS explícitas
sin credenciales/query/fragment/duplicados y prefijos/refnames sin traversal,
wildcards, backslash, whitespace o controles. No fija el remoto, URL ni prefijo
concretos en Python: esos valores viven en YAML. Validar otra configuración
sintácticamente válida no autoriza usarla. enabled=false es válido para cerrar
la capacidad, sin omitir validación de los restantes campos.
require_builder_capability conserva el requisito de implementación;
require_builder_publish_capability valida solo el prerrequisito de capacidad,
no resuelve aprobación ni ejecuta Git.

Publicar rama no equivale a merge, deploy, producción, technical approval ni
human approval. La futura ejecución debe registrar trazabilidad de Task Packet,
aprobación, identidad del Builder, rama/commit, destino autorizado y resultado,
sin credenciales. Esta tarea no añade GitPort.push, subprocess, CLI publish,
integración app/state-machine, inspección operacional de remotos/ramas, API de
GitHub, PR ni workflow dispatch. El ciclo existente no publica automáticamente.

Operational git push NOT IMPLEMENTED. No push, stage, commit ni tests ejecutados.
Bootstrap publication pendiente de revisión independiente y autorización futura.
La ampliación de alcance migra únicamente _valid_core_config en tests/test_cli.py;
no cambia comportamiento CLI ni sus assertions. Las pruebas del loader cubren
el nuevo contrato y rechazo legacy; permanecen NOT RUN. Los archivos del Safe
Runner y su ejecución deshabilitada no se modifican en este incremento.


## 26. COMMAND-EXECUTION-SAFETY-001: resolución sin ejecución local

**LOCAL PROJECT COMMAND EXECUTION = PROHIBITED.**

**LOGICAL AUTHORIZATION != EXECUTION AUTHORIZATION.**

Autorizar un logical command ID como unit, lint o build autoriza únicamente
su selección, resolución y tratamiento del argv como DATA. NO autoriza ejecutar
el argv ni confiar en el script, el código, los procesos hijos o sus efectos
secundarios.

Todo código/argv resoluble desde PROJECT_RULES continúa siendo UNTRUSTED para
ejecución hasta superar, en este orden:
1. Integrity / configuration admission aplicable;
2. Execution Safety Gate;
3. backend aislado aprobado.

PROJECT_RULES.commands define comandos/código del proyecto, no autoridad para
ejecutarlos en el host. Incluso python verify_task.py o pnpm.cmd test pueden
realizar operaciones arbitrarias. Una allowlist de ejecutables o denylist de
subcomandos no proporciona aislamiento. Candidate/project command != host
subprocess.

PERMISSIONS.execution_controls es un mapping cerrado obligatorio con una sola
clave: local_project_commands: false. El loader exige el booleano false exacto:
ausencia, true, 0, 1, "false", null y claves adicionales se rechazan con
ConfigError. No existe override por proyecto, Task Packet, entorno, CLI o agente.

El flujo transitorio es:
mandatory_tests -> resolve/validate -> isolated backend required ->
backend absent => BLOCKED BEFORE BUILDER.
El motivo público fijo es "isolated mandatory-test execution backend unavailable";
no incluye argv ni salidas. Aplica a ejecución fresca, probe y reanudación, antes
de invocar Builder o reservar una nueva unidad de ejecución. No modifica archivos
del proyecto mediante Builder ni ejecuta subprocess de tests.

resolve_mandatory_test conserva IDs lógicos, intersección con allowed_commands,
lookup exacto en PROJECT_RULES y argv como lista validada convertida en datos
inmutables. run_mandatory_test conserva la firma por compatibilidad, pero todo
intento termina cerrado; cwd/timeout son metadata sin efecto de ejecución.
No hay import de subprocess ni un segundo ejecutor local en test_runner.
Las pruebas históricas de reporting/review usan resultados sintéticos mediante
mocks exclusivamente en tests; no existe switch permisivo operacional.

Se conservan presupuestos, alcance, protected_paths, evidencia y sandbox del
Builder. El Git interno de evidence.py continúa bajo su control read-only,
separado de PROJECT_RULES.commands. La gobernanza de publicación controlada
(§25) permanece separada: un mapping publish: [git, push, ...] no concede la
capability publish_authorized_task_branch y nunca se ejecuta localmente.

SAFE TEST RUNNER es el backend previsto para candidate execution una vez
admitido y aprobado para integración. **No está integrado** por este incremento;
SAFE_TEST_EXECUTION_ENABLED=false permanece intacto. Las pruebas obligatorias
operacionales quedan BLOCKED; no se introduce dispatch, Docker ni acceso remoto.

PROJECT_RULES es entrada no confiable hasta la admisión de integridad (§28).
El bloqueo total elimina su ruta actual hacia subprocess mediante mandatory_tests.
GP-03b: IMPLEMENTED_PENDING_STATIC_REVIEW; no implica aprobación de contenido
ni sustituye la protección general de archivos de gobierno.
GP-01 y GP-02 permanecen pendientes del enforcement futuro de publicación
controlada. Este cambio no concede aprobación técnica ni habilita publicación.

## 27. TRUSTED SAFE RUNNER WORKFLOW IDENTITY

El workflow trusted `.github/workflows/safe-test-runner.yml` proviene del lado
de gobierno. Su identidad golden cubre el archivo completo: se leen bytes,
se reemplaza únicamente CRLF por LF y se rechaza cualquier CR restante.
No se normalizan espacios, indentación, quotes, comentarios, orden YAML ni
líneas vacías. SHA-256 canónico aprobado:
`722d0c0548e0243a2c9b3a2af8868bfd4963c65c39c8fcb1a46ba9f360250149`.

El contrato exige un archivo ordinario legible y el digest exacto. Un cambio
de contenido distinto de CRLF/LF implica contract failure. N-03 y N-04 quedan
mitigados mediante whole-workflow identity: tanto inserciones entre bloques
como representaciones YAML inline/flow cambian la identidad aunque eludan
una regex. Los tests estructurales permanecen como defense-in-depth.
La nueva prueba se incorpora para revisión estática; NOT RUN en esta tarea.

**TRUSTED WORKFLOW IDENTITY != WORKFLOW EXECUTION APPROVAL.**
La coincidencia demuestra WORKFLOW REVIEWED == WORKFLOW PRESENT; el hash es
identidad, NO autoridad. Builder NO puede considerar autorizado un cambio
actualizando simultáneamente workflow y golden digest. Todo cambio futuro
requiere Task Packet explícito, Mutation Boundary que incluya el workflow,
revisión del nuevo contenido, nueva identidad golden, revisión independiente
y aprobación aplicable antes de ejecución. Ejecutar sigue requiriendo
Execution Safety, gate específico y aprobación correspondiente.

Safe Runner permanece desactivado: SAFE_TEST_EXECUTION_ENABLED=false.
local_project_commands=false permanece intacto. Esta identidad no implica
integración, ejecución ni aprobación operacional del Safe Runner.

## 28. PROJECT_RULES INTEGRITY ADMISSION

GP-03b = **IMPLEMENTED_PENDING_STATIC_REVIEW**. PROJECT_RULES = UNTRUSTED INPUT
hasta admission. La ruta operacional única deriva de PROJECTS_DIR y del
project_id validado. Comprueba boundary resuelto, directorios ordinarios,
archivo ordinario y ausencia de symlink/reparse detectables; contrasta además
la identidad del descriptor abierto con la del archivo validado.
Missing/unreadable, redirección o escape fallan cerrado.

Se lee un único snapshot de bytes. Su SHA-256 y su parseo usan exactamente
el mismo objeto: **ADMITTED BYTES == PARSED BYTES == HASHED BYTES**.
El parser no reabre el path: UTF-8 estricto, Safe YAML específico de
PROJECT_RULES, rechazo recursivo de claves duplicadas, rechazo de secretos
y esquema cerrado. No modifica globalmente yaml.SafeLoader.
Las únicas claves son version, project_id, name, repo_path, commands,
protected_paths y autonomy_overrides. Version es integer 1 (no bool);
autonomy_overrides debe ser {} hasta que exista semántica implementada.
La resolución de repo_path y el matching profundo de protected_paths
conservan sus capas existentes. Commands conserva logical_id -> argv como DATA.

**ADMITTED STATE IS PINNED FOR THE CURRENT EXECUTION.** Un cambio posterior
en disco no reemplaza rules(A) por rules(B) ni amplía autoridad de la tarea.
Resume vuelve a admitir el archivo actual y compara project_rules_sha256
con el digest persistido; una diferencia bloquea antes del Builder.
El antiguo hash-before/load/hash-after podía hashear A y parsear B transitorio;
el snapshot elimina esa lectura operacional distinta.

**INTEGRITY ADMISSION != EXECUTION AUTHORIZATION.**
**PROJECT_RULES ADMISSION != COMMAND EXECUTION AUTHORIZATION.**
**LOGICAL AUTHORIZATION != EXECUTION AUTHORIZATION.**
La admisión demuestra ruta esperada, estructura, ausencia de claves duplicadas,
contenido/digest exactos y continuidad; no demuestra aprobación humana,
del Director ni corrección comercial. La autoridad final del contenido depende
de governance/protected publication/review. La protección general de archivos
de gobierno frente a cambios fuera de Mutation Boundary sigue siendo separada.
No se afirma inmunidad general frente a toda carrera del filesystem.

Los argv permanecen DATA: local_project_commands=false, backend aislado aún
requerido y SAFE_TEST_EXECUTION_ENABLED=false. Tests añadidos/migrados NOT RUN;
revisión estática y evidencia runtime de admisión pendientes. Sin cambios a
PROJECT_RULES reales, Safe Runner, permisos ni enforcement de publicación.

## 29. PERMISSIONS INTEGRITY ADMISSION

PERMISSIONS_ADMISSION = **IMPLEMENTED_PENDING_STATIC_REVIEW**.
PERMISSIONS es governance authority. Una ruta operacional única admite
CONFIG_DIR / PERMISSIONS.yaml como archivo ordinario, sin redirección final
symlink/reparse detectable ni escape del boundary. Reutiliza el control de
descriptor de PROJECT_RULES: el archivo abierto debe coincidir con el validado.
No se afirma inmunidad general frente a toda carrera del filesystem.

READ ONCE produce el snapshot RAW: **ADMITTED BYTES == HASHED BYTES == PARSED BYTES**.
El SHA-256 y el parser reciben el mismo objeto bytes; el parser no reabre el
archivo. UTF-8 estricto, Safe YAML local, rechazo de secretos y validadores
actuales de PERMISSIONS se conservan sin cambiar esquema ni YAML de gobierno.
Claves duplicadas, incluidas colisiones introducidas por merge, fallan cerrado.
Aliases seguros sin colisiones conservan semántica SafeLoader; ciclos y tags
inseguros se rechazan. yaml.SafeLoader global permanece intacto.

OrchestratorConfig usa permissions parseado del snapshot; POLICIES, AGENTS
y GATES conservan sus loaders/validadores actuales. Los consumidores públicos
de load_core_config también usan el parser desde bytes. La operación usa la
autoridad admitida aunque el archivo cambie posteriormente: esa modificación
no amplía permisos actuales. permissions_sha256 persiste como digest RAW sin
migración de Store; resume readmite y conserva la comparación fail-closed
con la identidad persistida antes de invocar Builder.

**PERMISSIONS INTEGRITY ADMISSION != ACTION AUTHORIZATION.**
**ACTION AUTHORIZATION != ACTION EXECUTION.**
La política de publicación admitida sigue siendo DATA: git push/publication
no está implementado por esta tarea; GP-01/GP-02 siguen pendientes de enforcement
operacional. local_project_commands=false, PROJECT_RULES.commands como DATA
y SAFE_TEST_EXECUTION_ENABLED=false permanecen intactos. Tests NOT RUN;
revisión estática, validación runtime y evidencia independiente pendientes.

## 30. PUBLICATION AUTHORITY FOUNDATION

CONTROLLED_PUBLICATION_AUTHORITY_FOUNDATION = **IMPLEMENTED_PENDING_STATIC_REVIEW**.
Autoridad directa = PERMISSIONS + POLICIES + GATES. Las tres requieren
continuidad de bytes exactos. La primitive interna de admisión de publicación
lee una vez cada archivo mediante el control compartido de ruta/descriptor:
ADMITTED BYTES == HASHED BYTES == PARSED BYTES. Devuelve config y los tres
SHA-256 RAW; no persiste ni aprueba. Es una admisión lógica, no una transacción
atómica del filesystem ni una garantía de continuidad hasta una ejecución futura.
AGENTS conserva su función de roster y no requiere snapshot completo.

POLICIES/GATES reutilizan el loader local de autoridad con UTF-8 estricto,
Safe YAML, rechazo recursivo de duplicados/colisiones de merge, secretos y
validadores completos existentes. Aliases seguros sin colisiones conservan
la política actual; yaml.SafeLoader global no cambia. El evaluador puro exige
capability aplicable, ambas habilitaciones, AMARILLO, DIRECTOR_INTERNAL_GATE,
BLOCKED y los dos flags del gate. No verifica aprobación, Git ni destino.

Task Packet incorpora authorized_actions opcional, lista cerrada cuyo único ID
es git_publish_task_branch. Ausencia o lista vacía => ninguna acción autorizada;
null, tipos incorrectos, duplicados e IDs desconocidos se rechazan.
authorizes_action expresa intención explícita como DATA, nunca permiso de ejecución.
No se infiere desde objective/scope, precondiciones o estados genéricos.

La rama proviene de packet.preconditions.git.expected_branch; la aprobación
futura exigirá approved_branch == packet.preconditions.git.expected_branch.
El destino permitido procede de PERMISSIONS admitido, no del Task Packet.
La aprobación específica posterior vinculará destino observado y commit final:
**INITIAL EXPECTED HEAD != FINAL APPROVED HEAD**. No se añade final_head.
TECH_APPROVED/HUMAN_APPROVED genéricos son insuficientes.

Builder nunca recibe autoridad directa para push: la futura publicación será
una primitive engine-owned. Aprobación específica del Director y publisher
siguen sin implementar; GP-01/GP-02 no están resueltos. No se altera Store,
CLI, estados ni YAML. local_project_commands=false y
SAFE_TEST_EXECUTION_ENABLED=false. Tests añadidos NOT RUN.

## 31. SPECIFIC CONTROLLED PUBLICATION APPROVAL

DIRECTOR_APPROVAL_MODEL = **IMPLEMENTED_PENDING_STATIC_REVIEW**.
ControlledPublicationApproval es un record frozen en memoria para la única
acción git_publish_task_branch. Liga approval_id, task_id, identidad RAW del
Task Packet, Builder, rama, SHA final del candidato, remote, URL efectiva
literal, target ref, identidades PERMISSIONS/POLICIES/GATES y timestamp con
zona horaria. Los digests usan 64 hex lowercase; el SHA Git actual usa 40.
Se rechazan valores vacíos, formatos placeholder y el identificador nulo.
La forma de un digest no prueba su origen: sus valores deben coincidir con
la admisión y las observaciones confiables suministradas.

El validador puro exige PublicationAuthoritySnapshot y aplica la intersección
solo a snapshot.config; OrchestratorConfig genérico no sirve como sustituto.
CP-02 queda resuelto estáticamente para esta entrada. Exige authorized_actions
explícito, igualdad con packet.preconditions.git.expected_branch y
target_ref == refs/heads/<branch>. El destino se compara literalmente con
PERMISSIONS admitido y el observado suministrado; no se obtiene de red/Git.
candidate_head_sha se compara con el candidato final suministrado, nunca se
sustituye por el expected_head inicial. No se resuelve otro Builder.

**REQUEST != APPROVAL.** No se necesita un request adicional ni Store para
este modelo/validador; no se emite, persiste ni selecciona una aprobación.
TECH_APPROVED, HUMAN_APPROVED y actor="director" son insuficientes.
approval_source solo admite EXTERNAL_TRUSTED_DIRECTOR como declaración de
procedencia requerida, NO como autenticación del emisor.
**APPROVAL_RECORD_VALID != APPROVAL_SOURCE_AUTHENTICATED.** La construcción
del record no concede autoridad: Builder no puede autoaprobarse. No existe
comando, transición, variable de entorno ni archivo mágico de emisión.
Ningún publisher puede usar todavía este record para ejecutar.

Todo mismatch invalida el binding actual; una aprobación diferente requiere
otro record. No hay semántica latest-wins: el futuro consumidor deberá exigir
approval_id explícita incluso ante múltiples records compatibles. La unicidad
persistente y la emisión autenticada se resolverán con su capa futura; no se
afirma que el modelo en memoria garantice autenticidad o unicidad global.

Pendientes: trusted Director issuance/authentication, observación exacta de URL
efectiva, Git preflight/TOCTOU/config isolation, GP-01/GP-02 publisher, Safe Runner
runtime, evidencia independiente y hardlink gap. Publisher sigue sin implementar.
AIP_ISO_001.yaml y PILOT_001.yaml permanecen como
PREEXISTING_INVALID_HISTORICAL_ARTIFACTS, sin modificar.
local_project_commands=false y SAFE_TEST_EXECUTION_ENABLED=false permanecen.
Tests de modelo y bindings añadidos NOT RUN; no se afirma TECH_APPROVED.

## 32. CONTROLLED PUBLICATION GIT PREFLIGHT

GIT_PUBLICATION_PREFLIGHT = **IMPLEMENTED_PENDING_STATIC_REVIEW**.
run_controlled_publication_git_preflight es observación READ-ONLY engine-owned.
Exige PublicationAuthoritySnapshot, ControlledPublicationApproval, Task Packet
con identidad RAW, Builder esperado y repo_path autorizado. Primero valida los
bindings conocidos de aprobación; después observa y vuelve a validar el SHA
final y destino efectivos. No obtiene autoridad de un OrchestratorConfig genérico.

La allowlist exacta contiene rev-parse --show-toplevel, rev-parse HEAD,
symbolic-ref --quiet --short HEAD, status --porcelain=v1 -z --untracked-files=all
--ignore-submodules=none, remote get-url --push --all <remote validado> y
config --no-includes --file - --null --list, ls-files --stage -z y
check-attr --stdin -z filter. Todos usan shell=False, cwd
autorizado y timeout. Overrides fijos core.fsmonitor=false y
core.untrackedCache=false impiden efectos de fsmonitor/cache en la observación.
El helper histórico de evidencia y su allowlist no se amplían.
Se rechazan filtros locales y gitlinks de submódulos antes de status para no
invocar filtros del proyecto ni observar configuraciones anidadas no admitidas.

Repo y .git deben ser directorios ordinarios sin redirección en sus componentes;
show-toplevel debe resolver exactamente al root autorizado. Linked worktrees,
commondir, config.worktree, extensions.worktreeConfig y core.worktree se rechazan.
Rama actual == approval.branch == packet.preconditions.git.expected_branch;
HEAD observado == candidate_head_sha aprobado. Detached HEAD falla cerrado.
INITIAL EXPECTED HEAD != FINAL APPROVED HEAD. Status debe estar completamente
vacío: cualquier entrada staged, modificada, borrada, renombrada, untracked o
en conflicto bloquea. El candidate actual sucio es EXPECTED_TO_BLOCK; no se limpia.

El entorno se construye sin heredar variables Git: GIT_CONFIG_NOSYSTEM=1,
GIT_CONFIG_GLOBAL apunta a un archivo ordinario vacío suministrado por el motor,
GIT_TERMINAL_PROMPT=0 y GIT_OPTIONAL_LOCKS=0. Los tests preparan ese archivo en
su scratch temporal. No se escriben configs ni se crean credenciales.

PF07 = IMPLEMENTED_PENDING_STATIC_REVIEW. GIT_ATTR_SOURCE se fija exactamente
a approval.candidate_head_sha, nunca HEAD dinámico ni expected_head inicial.
GIT_ATTR_NOSYSTEM=1 es engine-owned. core.attributesFile se fija mediante -c
al mismo archivo global vacío confiable, ordinario y sin reparse ya admitido;
core.worktree se fija mediante -c al root autorizado y validado. Bajo ese
contexto admitido, system attrs están deshabilitados, global attrs vacíos y
worktree .gitattributes sustituidos por los del candidate aprobado.
INFO_ATTRIBUTES_SUPPORTED=NO: presencia de .git/info/attributes, incluso vacío,
bloquea antes de Git y se comprueba nuevamente tras las observaciones.
check-attr consulta solo filter, con stdin NUL derivado de ls-files --stage -z;
se exige respuesta exacta por path con valor unspecified. Cualquier otro valor
o respuesta ambigua bloquea antes de status. Atributos normales text/eol/diff
y metadata no ejecutable siguen permitidos. Se mantiene el rechazo de filter.*
en config A. Una config B transitoria con filter.* no puede activar un driver
mediante las fuentes de atributos soportadas y admitidas.

PF03_FILTER_EXECUTION_VECTOR=NOT_CLOSED; PF03_GENERAL_ENDPOINT_RACE=PENDING.
Reutilizar el archivo vacío evita otra infraestructura, pero fijar su ruta no
fija sus bytes: un escritor concurrente podría cambiar la fuente global de
atributos/config entre admisión y uso. INFO_ATTRIBUTES_ENDPOINT_CHECK !=
CONTINUOUS_IMMUTABILITY: absent before/after no excluye creación/borrado ABA.
Bajo el contexto admitido y las fuentes soportadas, los filtros quedan
neutralizados/fail-closed; no se afirma inmunidad a toda carrera. La mutación
concurrente de metadata fuera del Mutation Boundary es una condición prohibida
que el futuro publisher debe aislar mediante Mutation Boundary / execution isolation.
PF-02, PF-04 y PF-06 permanecen sin cambios; PF-02 BLOCKS_PUBLISHER=YES.
Tests de atributos, marcador de filtro y config B añadidos NOT RUN.

.git/config se admite inicialmente como archivo ordinario; sus bytes A
producen SHA-256 RAW y se entregan a Git por stdin para parseo sin includes.
PF-01: después de la última observación Git y antes de devolver el resultado,
se readmite .git/config con el mismo control seguro y se exige igualdad
byte-for-byte con A, sin normalización ni equivalencia semántica. Diferencia
o fallo de readmisión bloquea. El resultado conserva sha256(A).
CONFIG_START == CONFIG_END no prueba CONFIG_NEVER_CHANGED_DURING_WINDOW:
no elimina TOCTOU/ABA ni introduce locking; la ejecución futura debe revalidar
inmediatamente en contexto controlado. PF-01=CLOSED; tests NOT RUN,
sin afirmación de validación runtime.
Todo include/includeIf se bloquea conservadoramente sin seguir cadenas.

remote get-url --push --all produce exactamente UNA URL: ausencia, múltiples
URLs o desigualdad literal frente a aprobación/PERMISSIONS bloquean. Se observa
pushurl por separado de fetch URL, y Git resuelve insteadOf/pushInsteadOf;
las entradas de rewrite se registran sin reconstruirlas ni normalizar destino.
Mirror/followTags/recursión/firma solo admiten ausencia o false/no/off/0;
valores ambiguos/duplicados, remote.<name>.push y push.pushOption bloquean.
core.hooksPath y pre_push_hook_present se registran. Solo se observa presencia:
no se lee ni ejecuta el hook. Paths de hooks fuera del repo, redirigidos o con
expansión ambigua se bloquean conservadoramente en este MVP.

El resultado frozen registra root, branch, SHA final, limpieza, remoto, URL,
ref, digest config, rewrites, ajustes de push, hooks, timestamp y las identidades
de aprobación/packet/autoridad. PRELIGHT OBSERVATION != EXECUTION AUTHORITY.
PREFLIGHT PASS != GIT PUSH != AUTHENTICATED DIRECTOR APPROVAL.
PREFLIGHT RESULT != ATOMIC EXECUTION GUARANTEE. El hash de config no elimina
todas las carreras: el futuro executor deberá revalidar inmediatamente repo,
branch, HEAD, clean status, URL efectiva, config local, target ref, approval y
autoridades; también deberá conservar el contexto de aislamiento y controlar hooks.

El futuro publisher deberá usar SHA candidato exacto (no HEAD dinámico), destino
literal aprobado, una refspec explícita única, sin force/tags/delete/recursión,
sin opciones implícitas ni prompts, y una estrategia explícita para controlar
o impedir el pre-push hook. No se construye todavía ese comando.
Emisión autenticada del Director y publisher siguen NOT_IMPLEMENTED.
local_project_commands=false y SAFE_TEST_EXECUTION_ENABLED=false permanecen.
Tests focalizados con repos temporales añadidos NOT RUN. Pendientes: trusted
Director issuance, runtime tests, publisher GP-01/GP-02, revalidación de ejecución,
Safe Runner runtime, evidencia independiente y hardlink gap.
