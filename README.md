# AI Operating System

## Назначение

AI Operating System (AI OS) — единый инженерный стандарт работы с AI-агентами в
рамках проектов.

## Единый стандарт для всех AI

Принципы AI OS применяются одинаково к GPT, Claude, Codex и другим AI-агентам,
подключаемым к проектам. Стандарт не зависит от конкретного поставщика модели.

## Изменение стандарта

Любые изменения стандарта AI OS вносятся только через Pull Request.

## Использование как Template Repository

Репозиторий содержит готовые шаблоны для старта нового проекта под управлением
AI OS:

- `.github/ISSUE_TEMPLATE/` — шаблоны GitHub Issue (bug report, feature
  request);
- `.github/PULL_REQUEST_TEMPLATE.md` — шаблон Pull Request;
- `templates/AGENTS.md` — шаблон AGENTS.md для нового проекта;
- `templates/README.md` — шаблон README.md для нового проекта;
- `templates/adr/ADR_TEMPLATE.md` — шаблон Architecture Decision Record;
- `templates/EXAMPLE_PROJECT_STRUCTURE.md` — пример рекомендуемой структуры
  нового проекта.

Скопируйте нужные шаблоны в новый проект и адаптируйте под задачу, не нарушая
принципы `AI_OS.md`.
