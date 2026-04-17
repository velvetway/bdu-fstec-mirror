# bdu-fstec-mirror

Неофициальное зеркало базы данных угроз ФСТЭК России (БДУ ФСТЭК) для использования из окружений, где оригинальный сайт `bdu.fstec.ru` недоступен из-за геоблокировки.

## Что здесь

| Файл | Описание | Формат | Размер |
| --- | --- | --- | --- |
| `data/vulxml.xml.gz` | Полная выгрузка уязвимостей БДУ | XML (gzip) | ~28 МБ |
| `data/vullist.xlsx` | Уязвимости в табличном виде | XLSX | ~29 МБ |
| `data/thrlist.xlsx` | Список угроз из БДУ | XLSX | ~96 КБ |
| `data/stats.json` | Метаинформация снимка | JSON | — |

Текущий снимок:
- **Всего записей:** 86 664
- **Идентификаторы:** `BDU:2014-00001` → `BDU:2026-05547`
- **Последнее обновление источника:** 31.12.2025
- **Дата снимка:** 18.04.2026

## Зачем

Сайт `bdu.fstec.ru` геоблокирует все не-российские IP. Это значит, что CI-облака (GitHub Actions на ubuntu-latest, AWS, Azure, Google Cloud), сторонние security-тулы и LLM-сервисы (вроде Claude) не могут напрямую загружать данные БДУ.

Это зеркало снимает блок: любое окружение может забрать `vulxml.xml.gz` через `raw.githubusercontent.com` и получить тот же набор данных.

## Использование

### Напрямую (curl)

```bash
curl -L https://github.com/velvetway/bdu-fstec-mirror/raw/main/data/vulxml.xml.gz \
  | gunzip > vulxml.xml
```

### Python

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

### Структура записи

```xml
<vul>
  <identifier>BDU:2024-01234</identifier>
  <name>Уязвимость ...</name>
  <description>...</description>
  <vulnerable_software>...</vulnerable_software>
  <cwes><cwe>...</cwe></cwes>
  <identify_date>01.01.2024</identify_date>
  <publication_date>...</publication_date>
  <last_upd_date>...</last_upd_date>
  <cvss><vector score="7.5">...</vector></cvss>
  <severity>...</severity>
  <solution>...</solution>
  <identifiers>
    <identifier type="CVE" link="...">CVE-2024-...</identifier>
  </identifiers>
</vul>
```

## Обновление снимка

Обновление пока выполняется вручную с IP российского региона. Скрипт обновления:

```bash
# С RU-машины
curl -o vulxml.xml https://bdu.fstec.ru/files/documents/vulxml.xml
curl -o vullist.xlsx https://bdu.fstec.ru/files/documents/vullist.xlsx
curl -o thrlist.xlsx https://bdu.fstec.ru/files/documents/thrlist.xlsx
gzip -9 vulxml.xml

# Коммит в репозиторий
git add data/ && git commit -m "data: snapshot YYYY-MM-DD" && git push
```

Принимаются PR с обновлёнными снимками.

## Правовая сторона

- Данные БДУ — публичная информация, размещённая ФСТЭК России на своём сайте.
- Этот репозиторий не аффилирован с ФСТЭК России.
- Код и структура репозитория распространяются под MIT. **Данные остаются собственностью ФСТЭК России.**
- При использовании данных указывайте источник: `https://bdu.fstec.ru`.

## Связанные проекты

- [velvetway/minreestr-mcp](https://github.com/velvetway/minreestr-mcp) — MCP-сервер для поиска российского ПО в каталоге (ФСТЭК-сертифицированное ПО).
- MCP-сервер для работы с этим зеркалом — в разработке.
