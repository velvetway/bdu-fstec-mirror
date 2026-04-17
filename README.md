# bdu-fstec-mirror — БДУ ФСТЭК скачать без геоблока

[![Snapshot](https://img.shields.io/badge/snapshot-2026--04--18-informational)](data/stats.json)
[![Vulnerabilities](https://img.shields.io/badge/vulnerabilities-86%2C664-success)](data/stats.json)
[![BDU range](https://img.shields.io/badge/BDU-2014--00001%20%E2%86%92%202026--05547-blue)](data/stats.json)
[![Source](https://img.shields.io/badge/source-bdu.fstec.ru-lightgrey)](https://bdu.fstec.ru/vul)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Публичное зеркало **Банка данных угроз безопасности информации ФСТЭК России (БДУ ФСТЭК, bdu.fstec.ru)**. Скачать полную выгрузку уязвимостей можно одной командой `curl` — без VPN, без российского IP, без регистрации. Обновляется на регулярной основе.

Подходит для: CI/CD (GitHub Actions `ubuntu-latest`, AWS, Azure, GCP), LLM-сервисов (Claude, OpenAI), security-тулов (vulners, OpenCTI, Trivy-совместимых сканеров), собственных систем управления уязвимостями и compliance по 152-ФЗ / 187-ФЗ / ГОСТ Р 57580.

**Почему это нужно:** оригинальный сайт `bdu.fstec.ru` блокирует все не-российские IP-адреса, что ломает интеграции из зарубежных облаков и CI. Прямых официальных API у ФСТЭК нет, дампы самостоятельно не публикуются. Это зеркало снимает блок и раздаёт тот же набор данных через GitHub-CDN.

## Что здесь

| Файл | Описание | Формат | Размер |
| --- | --- | --- | --- |
| `data/vulxml.xml.gz` | Полная XML-выгрузка уязвимостей | gzip(XML) | ~28 МБ |
| `data/bdu.sqlite.gz` | Готовая SQLite-база c FTS5-индексом | gzip(SQLite) | ~50 МБ |
| `data/vullist.xlsx` | Уязвимости в табличном виде | XLSX | ~29 МБ |
| `data/thrlist.xlsx` | Список угроз из БДУ | XLSX | ~96 КБ |
| `data/stats.json` | Метаинформация снимка | JSON | — |

Текущий снимок:

- **Всего записей:** 86 664
- **Идентификаторы:** `BDU:2014-00001` → `BDU:2026-05547`
- **Последнее обновление источника:** 17.04.2026
- **Дата снимка:** 18.04.2026
- **Схема SQLite:** `schema_version = 3`

## Зачем

Сайт `bdu.fstec.ru` геоблокирует все не-российские IP. Это значит, что CI-облака (GitHub Actions на `ubuntu-latest`, AWS, Azure, Google Cloud), сторонние security-тулы и LLM-сервисы (Claude Cloud) не могут напрямую загружать данные БДУ.

Это зеркало снимает блок: любое окружение тянет `vulxml.xml.gz` или `bdu.sqlite.gz` через `raw.githubusercontent.com` и получает тот же набор данных.

## Использование

### Быстрый старт через SQLite

```bash
curl -L https://github.com/velvetway/bdu-fstec-mirror/raw/main/data/bdu.sqlite.gz \
  | gunzip > bdu.sqlite
sqlite3 bdu.sqlite "SELECT id, name FROM vulnerabilities WHERE identify_year=2024 AND severity_level>=4 LIMIT 5;"
```

```bash
# Поиск по FTS5 (с токенизацией кириллицы и ранжированием BM25)
sqlite3 bdu.sqlite "SELECT v.id, substr(v.name,1,80) FROM vulnerabilities_fts f JOIN vulnerabilities v ON v.rowid=f.rowid WHERE vulnerabilities_fts MATCH 'Astra Linux' ORDER BY rank LIMIT 5;"
```

### Python (XML)

```python
import gzip
import urllib.request
import xml.etree.ElementTree as ET

url = "https://github.com/velvetway/bdu-fstec-mirror/raw/main/data/vulxml.xml.gz"
with urllib.request.urlopen(url) as r, gzip.open(r) as f:
    root = ET.parse(f).getroot()
    for vul in root.findall("vul"):
        print(vul.findtext("identifier"), vul.findtext("name"))
```

## Схема SQLite

Основные таблицы:

- `vulnerabilities` — одна запись БДУ на строку. Колонки: `id`, `name`, `description`, `software_names`, `vendors`, `cves_joined`, `severity`, `severity_level` (1-4), `cvss_score`, `cvss_vector`, `identify_date`, `publication_date`, `last_upd_date`, `identify_year`, `solution`, `status`, `exploit_status`, `fix_status`, `has_exploit`, `has_fix`, `sources`.
- `cves` (`bdu_id`, `cve_id`) — связь многие-ко-многим с CVE.
- `cwes` (`bdu_id`, `cwe_id`) — привязка к типам уязвимостей.
- `software` (`bdu_id`, `name`, `vendor`, `version`) — уязвимое ПО.
- `vulnerabilities_fts` — FTS5-индекс (external content) по полям `name`, `description`, `software_names`, `vendors`, `cves_joined`. Токенизатор `unicode61 remove_diacritics 2`.
- `metadata` (`key`, `value`) — `snapshot_date`, `total`, `schema_version`.

Composite-индексы для типовых фильтров:

- `idx_vul_year_cvss (identify_year, cvss_score DESC)`
- `idx_vul_severity_cvss (severity_level, cvss_score DESC)`
- `idx_vul_cvss_year (cvss_score DESC, identify_year)`

## Автоматическая пересборка

`data/bdu.sqlite.gz` и `data/stats.json` пересобираются GitHub Action `.github/workflows/build-db.yml` каждый раз, когда меняется `data/vulxml.xml.gz` или `scripts/build_db.py`. Ручная сборка:

```bash
python scripts/build_db.py \
  --xml data/vulxml.xml.gz \
  --db data/bdu.sqlite \
  --snapshot-date 2026-04-18
```

## Обновление снимка

XML-источник надо качать с IP российского региона (у `bdu.fstec.ru` геоблок):

```bash
# С RU-машины
curl -o vulxml.xml https://bdu.fstec.ru/files/documents/vulxml.xml
curl -o vullist.xlsx https://bdu.fstec.ru/files/documents/vullist.xlsx
curl -o thrlist.xlsx https://bdu.fstec.ru/files/documents/thrlist.xlsx
gzip -9 vulxml.xml

git add data/vulxml.xml.gz data/vullist.xlsx data/thrlist.xlsx
git commit -m "data: snapshot YYYY-MM-DD"
git push
# SQLite пересоберётся автоматически через GitHub Action.
```

Принимаются PR с обновлёнными снимками из других источников — главное, чтобы XML был оригинальным.

## Правовая сторона

- Данные БДУ — публичная информация, размещённая ФСТЭК России на своём сайте.
- Этот репозиторий не аффилирован с ФСТЭК России.
- Код и структура репозитория распространяются под MIT. **Данные остаются собственностью ФСТЭК России.**
- При использовании данных указывайте источник: `https://bdu.fstec.ru`.

## Ключевые слова / Keywords

БДУ ФСТЭК, банк данных угроз, уязвимости ФСТЭК, BDU FSTEC, российская база уязвимостей, Russian vulnerability database, BDU mirror, ФСТЭК XML dump, bdu.fstec.ru API, ФСТЭК JSON, cybersecurity 152-ФЗ 187-ФЗ compliance, ГОСТ Р 57580, CVE mapping Russia, threat intelligence Russia, киберриски РФ.

## Связанные проекты

- [velvetway/bdu-fstec-mcp](https://github.com/velvetway/bdu-fstec-mcp) — MCP-сервер для Claude поверх этого зеркала.
- [velvetway/minreestr-mcp](https://github.com/velvetway/minreestr-mcp) — MCP для поиска российского ПО в каталогпо.рф.

## FAQ

### Насколько часто обновляется?

Снимок пересобирается при любом пуше нового `vulxml.xml.gz` через GitHub Action. Типичная частота — раз в 1–2 недели, зависит от готовности подтянуть свежий XML с RU-источника.

### Это легально?

Данные БДУ — публичная информация в силу 149-ФЗ. ФСТЭК публикует их на своём сайте без ограничений по доступу (только геоблок по инфраструктуре). MIT-лицензия распространяется на код репозитория. Данные остаются собственностью ФСТЭК России.

### Чем лучше vulners / opencve / CVE Details?

Эти сервисы не содержат идентификаторов БДУ (`BDU:YYYY-NNNNN`). Для российской compliance-работы требуется именно БДУ — в документах по 187-ФЗ, моделях угроз, паспортах КИИ ссылаются на BDU-идентификаторы, не на CVE.

### Можно ли положить это в свой security-тул?

Да. Достаточно забрать `data/bdu.sqlite.gz` — получаете 86k записей + FTS5-индекс с нулевыми инфраструктурными требованиями. Примеры интеграции: vulners-сканеры, OpenCTI-коннекторы, Trivy-плагины, собственные SIEM-обогатители.

### Как помочь?

PR с обновлёнными снимками XML из любых российских источников, а также issue, если сайт-источник изменил формат.
