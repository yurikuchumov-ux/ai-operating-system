# P0 Partner Preview: инструкция партнёра

> **UNTRUSTED PREVIEW.** Этот workflow не имеет права записи или публикации
> в репозиторий. Author job и все результаты провайдера недоверенны. Отдельный
> packaging job проверяет только структуру артефакта и границы immutable task.
> Он не подтверждает корректность, добросовестность, происхождение, безопасность,
> прохождение тестов или готовность к production. Человек обязан проверить каждый
> изменённый байт, вручную применить выбранные изменения и первый раз выполнить
> их только в CI без секретов и прав записи.

## Что это за Preview

Partner Preview — временный помощник для ускорения разработки, пока полноценный
P0 v2 строится отдельно. Он принимает точную immutable task, показывает Claude
только небольшой явно разрешённый набор исходников и возвращает недоверенный
patch для ручной проверки.

Он ничего не коммитит, не отправляет в GitHub, не создаёт PR или Check Run, не
меняет branch protection, не запускает созданный код и не делает merge.

```text
prepare (contents: read, без OAuth)
  └─ точная task + clean base
     └─ санитарный набор UTF-8 файлов, без .git/.claude/.mcp.json
        ↓
author (permissions: {}, только отдельный Claude OAuth)
  └─ Claude редактирует candidate/
     └─ один недоверенный JSON snapshot
        ↓
package (contents: read, без OAuth, новый runner)
  └─ заново получает task + clean base
     └─ проверяет формат/пути/размеры и создаёт:
        ├─ UNTRUSTED-PREVIEW.json
        ├─ changes.patch
        └─ summary.md
             ↓
          человек
             ↓
  ручное применение → первый secretless read-only CI
```

## Зафиксированная авторизация этой реализации

- Repository: `yurikuchumov-ux/ai-operating-system`
- Issue: `#68`
- Implementation branch: `agent/issue-68-partner-preview`
- Exact base: `d4f10b714de3afae84d48dfcd3daa6405092a973`
- Superseded task v1 commit:
  `3ddb03f1ac1a6bea48f590d99b0196b1deae3cd9`
- Active task v2 commit:
  `950b7ffd2ea36970ba01b140958416f9b0621535`
- Active task path:
  `.ai/tasks/68/p0-partner-preview-task.v2.json`
- Active task SHA-256:
  `7ccb5fd10bc264aa20cc0b3cac56aec985f90010be6a1f5fc2bbb3f5e8f15b46`
- Pro review prompt SHA-256:
  `32ffe7e8a75af4417f6ac7a416a917fb04ad56d7129d39ce44e8cb10d8067004`
- Pro review result SHA-256:
  `832891fd2c35b1310d87f4099af169e508196a782f20790066a65c9f2228cce8`
- Pro verdict: `REQUEST_CHANGES`; обязательные изменения встроены в эту
  трёхступенчатую архитектуру.
- Claude action:
  `anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8`
- Workflow blob SHA-256:
  `0d94104560dd7ca6cabf4a4fa13332c495e8beb1ef4d4b31c3a6937486926e6f`

PR #69 остаётся Draft и unmerged. Этот Preview не одобряет PR #69, старый P0,
P0 v2, required check или production execution spine. Merge запрещён без
отдельного явного решения владельца.

## Один раз перед передачей партнёру

Владелец репозитория:

1. Проверяет точный implementation commit и отдельно сообщает его партнёру.
   SHA нельзя заменять названием ветки.
2. Создаёт отдельный, независимо отзываемый subscription-backed
   `CLAUDE_CODE_OAUTH_TOKEN`. Anthropic API key не используется.
3. Сохраняет token как repository secret `CLAUDE_CODE_OAUTH_TOKEN` только для
   этой Preview-операции.
4. Создаёт repository variable `P0_PARTNER_PREVIEW_ENABLED=true`.
5. Разрешает обработку только публичных, синтетических или явно согласованных
   low-sensitivity исходников. Production-секреты и конфиденциальные данные
   запрещены.
6. Проверяет numeric repository ID и owner ID в GitHub, не выводя секреты в
   логи.

Один Preview-run одновременно. Workflow использует общую concurrency group и
не отменяет уже работающий запуск.

## Требования к immutable task партнёра

Task должна:

- быть доступна по полному 40-символьному commit SHA;
- пройти `contracts/schemas/task.v1.schema.json`;
- ссылаться на этот repository и точный clean `base_sha`;
- содержать максимум 64 точных `allowed_paths`, без glob;
- не разрешать `.git`, `.claude`, `.mcp.json`, `CLAUDE.md`, output-файлы
  Preview или другие control paths;
- перечислять необязательные read-only context paths только как
  `acceptance_criteria[].parameters.preview_context_paths`;
- не пересекать editable и context paths;
- использовать только UTF-8 текст: максимум 1 MiB на файл и 8 MiB суммарно.

Context paths также передаются Anthropic. Добавляйте только минимально
необходимые файлы.

## Как запустить

### Срочный local/manual режим — доступен без merge

Это единственный режим, который можно передать партнёру до появления Preview
workflow в default branch. Он использует subscription-backed интерактивный
Codex/Claude/ChatGPT, а не платный API.

Подготовьте три независимых каталога:

- `implementation/` — clean checkout точного owner-provided implementation SHA;
- `baseline/` — clean checkout `base_sha` из immutable task;
- `control/` — точный task JSON из `task_commit`.

Проверьте task и создайте санитарный provider input:

```bash
python3 implementation/tools/validate_b0.py validate \
  --type task \
  --document control/task.json

python3 implementation/tools/p0_partner_preview.py prepare \
  --task control/task.json \
  --schema implementation/contracts/schemas/task.v1.schema.json \
  --baseline baseline \
  --output provider-input
```

Дайте интерактивному subscription-backed AI доступ только к каталогу
`provider-input/`. Не открывайте ему `implementation/`, `baseline/`, исходный
repository с `.git`, credentials, production data или другие каталоги. Prompt
должен требовать прочитать `TASK.json` и `INSTRUCTIONS.md`, читать context только
из `context/` и менять только точные пути внутри `candidate/`.

После завершения AI закройте его доступ к каталогу. Создайте snapshot только
чистой копией helper из `implementation/`, которую AI не видел и не мог менять:

```bash
python3 implementation/tools/p0_partner_preview.py snapshot \
  --task provider-input/TASK.json \
  --schema implementation/contracts/schemas/task.v1.schema.json \
  --candidate provider-input/candidate \
  --output candidate.snapshot.json

python3 implementation/tools/p0_partner_preview.py package \
  --task control/task.json \
  --schema implementation/contracts/schemas/task.v1.schema.json \
  --baseline baseline \
  --snapshot candidate.snapshot.json \
  --output final-package
```

Local/manual режим также не является OS sandbox. Передавать AI можно только
публичные, синтетические или отдельно согласованные low-sensitivity bytes.
Папки `implementation/` и `baseline/` нельзя размещать внутри
`provider-input/`.

### Hosted GitHub Actions режим — только после отдельного owner approval

GitHub принимает событие `workflow_dispatch` только когда соответствующий
workflow существует в default branch. Поэтому наличие файла на
`agent/issue-68-partner-preview` само по себе не создаёт кнопку запуска.

Никогда не merge Preview workflow автоматически. До отдельного явного решения
владельца используйте local/manual режим выше. Перед разрешённым merge нужны:

1. review точного implementation head и workflow blob;
2. secretless synthetic canary;
3. подтверждение, что author job не получил repository access;
4. проверка запрещённых Claude tools и sensitive host reads;
5. отдельное явное owner approval на merge Preview workflow.

После выполнения этих gate:

Откройте Actions → **UNTRUSTED PREVIEW — P0 Partner Preview** и выберите
**Run workflow** на точном независимо проверенном implementation commit.

Заполните:

- `task_commit` — полный immutable task SHA;
- `task_path` — точный `.ai/tasks/...json`;
- `expected_implementation_sha` — SHA, полученный от владельца по независимому
  каналу;
- `expected_repository_id` и `expected_owner_id` — numeric IDs;
- `expected_operator` — точный GitHub login оператора;
- `acknowledgement` —
  `I UNDERSTAND THIS IS AN UNTRUSTED PREVIEW`.

Workflow проверяет, что:

- gate variable равна `true`;
- `github.actor` и `github.triggering_actor` совпадают с оператором;
- `github.workflow_sha` равен ожидаемому implementation SHA;
- repository/owner IDs совпадают;
- task ref и path имеют точную безопасную форму.

Несовпадение останавливает run до OAuth-bearing шага.

## Что скачать

При успехе скачайте ровно один финальный artifact:

`UNTRUSTED-PREVIEW-<run_id>-<run_attempt>`

Не подменяйте его артефактом другого run или attempt. Внутри должно быть ровно
три обычных файла:

1. `UNTRUSTED-PREVIEW.json`
2. `changes.patch`
3. `summary.md`

Не открывайте и не выполняйте файлы автоматически. Сначала перечислите entries,
размеры и SHA-256 в disposable directory. Сверьте `run_id`, `run_attempt`,
task SHA, base SHA, workflow SHA и workflow blob SHA.

`scope_of_serialized_snapshot_checked=true` означает только, что сериализованные
bytes относятся к `allowed_paths`. Это не означает, что provider был изолирован
как hostile OS process, что patch доброкачественный или что исходный provider
workspace полностью отражён в snapshot.

## Обязательная ручная проверка

Партнёр должен:

1. Сравнить каждый изменённый путь с immutable task.
2. Прочитать каждый изменённый байт и найти неожиданные сетевые вызовы,
   процессы, install hooks, encoded payloads, bidi/zero-width символы,
   изменения auth/crypto/CI/deployment.
3. Не доверять тексту Claude, логам action, Markdown, ссылкам и заявлениям об
   успехе.
4. В чистой disposable-ветке сначала выполнить:

   ```bash
   git apply --check changes.patch
   git apply changes.patch
   git diff --check
   git diff --stat
   git diff
   ```

5. Вручную выбрать, исправить или отбросить изменения.

Workflow/dependency/build/auth/crypto/CI/deployment-изменения требуют второго
человека-рецензента.

## Первый запуск созданного кода

Первый CI обязан быть **secretless и read-only**:

- `permissions: {}` или только необходимое `contents: read`;
- без repository/environment/organization secrets;
- без `id-token: write`;
- без deploy/package/signing credentials;
- без self-hosted runner;
- без production/internal network;
- без общего writable cache;
- без privileged container и Docker socket;
- без права commit, push, PR, Check Run, status или release.

Clean checkout защищает от части Git-metadata атак, но не делает AI-код безопасным.
Обычный CI разрешён только после полного human source review и
явного принятия риска выполнения.

## Когда немедленно остановиться

Preview считается проваленным, если:

- admission, author или package job завершился неуспешно;
- run отменён или истёк timeout;
- отсутствует artifact текущего run/attempt;
- кто-либо предлагает debug rerun;
- обнаружены неожиданные пути, metadata, token-like bytes или содержимое;
- Claude смог прочитать чувствительные host paths или использовать запрещённый
  инструмент;
- зафиксирована любая неожиданная GitHub mutation или внешняя активность;
- первый secretless CI нельзя обеспечить.

Для остановки владелец устанавливает `P0_PARTNER_PREVIEW_ENABLED=false` и
отзывает отдельный OAuth credential. Отзыв может вступить в силу не мгновенно.
Debug rerun допустим только в новом disposable repository с новым disposable
credential и без данных партнёра.

## Честные остаточные риски

- Pinned top-level action, его зависимости и устанавливаемый Claude runtime не
  полностью content-bound.
- Action/runtime получает reusable OAuth credential и может украсть или
  использовать его до фактического отзыва.
- Ограничение Claude tools уменьшает обычные возможности модели, но не является OS sandbox
  или containment action/runtime.
- Action всё равно выполняет shell, dependency installers, сеть и попытку Git
  setup; отсутствие Bash tool у модели не отменяет этого.
- Разрешённые task/context bytes отправляются Anthropic.
- Patch может быть ошибочным, вредоносным, backdoored, небезопасным или
  вводящим в заблуждение.
- Human review и secretless CI снижают риск, но не доказывают добросовестность.
- GitHub-hosted runner, Actions и artifact service остаются доверенной
  инфраструктурой.
- Native action logs и Claude report недоверенны и не обязаны содержать marker
  `UNTRUSTED PREVIEW`.
- Provider/action compromise может получить runner state и Actions command
  channels.
- Packaging проверяет структуру и task scope, но не correctness, security,
  licensing, provenance или test success.
- Preview запрещён для confidential production data, production credentials,
  arbitrary third-party repositories и untrusted fork content.

## Ограничения Preview по сравнению с P0 v2

Preview не публикует результат и не формирует trusted verification evidence.
У него нет полноценного dedicated UID/OS sandbox, cgroup-lifecycle proof,
content-bound runtime, verifier-owned evidence, безопасного publisher и
finalizer. Эти свойства относятся к отдельной работе над P0 v2.
