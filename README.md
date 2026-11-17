# Java4Shell · инвентаризация Java

Сервис ищет **Java 17 от 17.0.6 включительно**. Это критерий отбора для проверки, применяемый к известной версии. Ветки 8, 11, 21 и другие сохраняются в полном отчёте с признаком `outside_scope`. Обозначение `17` без номера обновления получает `unknown_version`. Статус `candidate` означает совпадение с правилом инвентаризации. Применимость CVE к конкретной сборке проверяют по бюллетеню производителя.

[Схема draw.io](docs/architecture.drawio) · [Интерактивная карта HTML](docs/architecture.html)

## Запуск

Требуется Docker с Compose 2.30+ для чтения `env_file` в режиме `raw`. В PowerShell из папки проекта:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Укажи реальные адреса и учётные данные в .env.
docker compose up -d --build --wait
```

Открой [веб-интерфейс](http://localhost:8080). Порт задаёт `JAVA4SHELL_PORT`. После изменения `.env` выполни `docker compose up -d --force-recreate`. Compose публикует интерфейс на loopback. Отчёты сохраняются в `reports/` на хосте. Веб-интерфейс показывает состояние и ссылки последнего запуска каждого источника с момента запуска сервиса.

### Подключения

| Источник | Параметры в `.env` |
| --- | --- |
| Bitbucket Data Center | `BITBUCKET_URL` с контекстным путём, если он используется, и `BITBUCKET_TOKEN` с правом чтения репозиториев |
| Bitbucket Cloud | `BITBUCKET_CLOUD_WORKSPACE`, `BITBUCKET_CLOUD_EMAIL` и `BITBUCKET_CLOUD_TOKEN` для API token. Для Bearer access token email оставь пустым |
| Nexus REST | `NEXUS_URL` и `NEXUS_REST_USERNAME`/`NEXUS_REST_PASSWORD` для Basic или `NEXUS_TOKEN` для Bearer при поддержке на стороне сервера |
| Nexus Docker Registry | `NEXUS_REGISTRIES` в формате JSON, например `{"docker-hosted":"https://docker.example.com:18443"}`. Для Docker-аутентификации укажи `NEXUS_DOCKER_USERNAME`/`NEXUS_DOCKER_PASSWORD` |

Для GUI платформа выбирается в форме. В CLI исходный режим задаёт `BITBUCKET_PROVIDER` или флаг `--provider`. Значения секретов остаются в окружении сервиса. Формат Compose `raw` сохраняет специальные символы, включая `$`. В `.env` записывай значения без кавычек. Для защищённых корпоративных сервисов используй HTTPS и доверенный сертификат. Переменные `BITBUCKET_ALLOW_HTTP_AUTH=1` и `NEXUS_ALLOW_HTTP_AUTH=1` разрешают аутентификацию по HTTP для изолированного стенда.

Для Docker групп указывай имена отдельных репозиториев-участников. У каждого должен быть собственный корректный endpoint в `NEXUS_REGISTRIES`, чтобы одноимённые образы из разных репозиториев не смешивались. При развертывании в контейнере `localhost` указывает на сам контейнер. Для опубликованных на Docker Desktop тестовых портов используй `host.docker.internal`.

## Как проходит опрос

1. **GUI** передаёт фильтры и задержку локальному Python API. Можно одновременно выполнять по одному опросу Bitbucket и Nexus. Токены читаются из `.env`.
2. **Bitbucket** перечисляет доступные репозитории через REST с пагинацией. Проверяет основную ветку и дополнительные ветки по маскам. В режиме Cloud перечисляет дерево директорий по commit hash, в Data Center использует список файлов на конкретном коммите. Проверяет Dockerfile, Containerfile, YAML, POM, Gradle, Jenkinsfile и файлы выбора JDK. Различает цель компиляции, декларацию JDK сборки, ссылку на образ и базу Docker-стадии. Разрешает локальные Maven properties и Docker ARG перед первым FROM. Внешние родительские POM, динамические CI-шаблоны и установка Java произвольными shell-командами могут требовать ручной проверки.
3. **Nexus** перечисляет Docker hosted-репозитории и по запросу proxy, затем проходит страницы assets. Разрешает теги в digest, раскрывает индексы OCI/Docker и проверяет каждый платформенный manifest. Убирает дубликаты тегированных манифестов, которые Nexus дополнительно перечисляет под digest. Сохраняет отдельные теги и реально нетегированные манифесты. Один digest экспортируется один раз за запуск. В финальной файловой системе ищет метаданные Java `release` рядом с `bin/java` или библиотекой JVM. Если найден исполняемый файл JVM с неизвестной версией, он остаётся в JSON. Файлы образов не исполняются. Анализ нестандартных runtime и дистрибутивов без файла `release` может дать неполную версию.
4. **Статистика** обновляется во время работы. Отчёт показывает количество REST GET, ошибки, последний HTTP-статус, последнее, среднее и максимальное время ответа. Задержка `0.1` секунды по умолчанию применяется между завершением предыдущего REST GET и началом следующего. Время ожидания показателей REST не включает эту задержку. Для операций Registry отдельно отображается время команд `crane`. Внутренние HTTP-вызовы `crane` используют собственный сетевой клиент.
5. **Отчёты**. `candidates.csv` содержит совпадения с порогом. `inventory.json` содержит все находки, перечень обработанных объектов, данные об охвате и ошибки. Для Bitbucket доказательство содержит commit, файл и строку. Для образа сохраняются digest, платформа, версия, производитель при наличии и путь к файлу. Доступные репозитории ограничены правами учётной записи. Веб-отчёты размещаются в `reports/<источник>/<id запуска>/`.

## CLI

CLI работает на Python 3.11+ без сторонних Python-пакетов. Для Nexus нужен `crane` в PATH, при запуске через Compose он уже входит в образ.

```powershell
python bitbucket_inventory.py --provider datacenter --project APP --branch 'release/*' --delay 0.1
python bitbucket_inventory.py --provider cloud --project J4S01 --delay 0.2
python nexus_inventory.py --repository java4shell-fixtures --delay 0.1
```

По умолчанию Bitbucket проверяет основную ветку. Для всех веток передай `--branch '*'`. Для Nexus можно передать `--include-proxy`. CLI возвращает код 2 при ошибках охвата и сохраняет доступные результаты. Опция `--progress` выводит события HTTP и операций Registry для мониторинга.

## Dependency-Track

В веб-интерфейсе Dependency-Track открой **Components → Coordinates**. Искать удобнее по **Name**, например `openjdk-17-jre-headless`, `openjdk-17-jdk`, `temurin` или `corretto`. Поле **Version** оставь пустым и проверь версии в результатах. Для старых версий проектов отключи **Only show latest project versions**. Поиск охватывает компоненты из загруженных SBOM. Для версии JVM нужен SBOM, в котором сам JDK или JRE представлен компонентом. [Форма поиска Dependency-Track 4.14](https://github.com/DependencyTrack/frontend/blob/4.14.x/src/views/portfolio/components/ComponentSearch.vue)

## Проверка

```powershell
python -m unittest discover -s tests -v
docker compose config --quiet
docker compose up -d --build --wait
python tests/check_live.py --url http://127.0.0.1:18084
```

Модульные и интеграционные тесты запускаются без токенов. Они проверяют границы версий, пагинацию и задержку REST на локальном Data Center API, режим Cloud на фикстурах, файлы рантайма, мультплатформенные манифесты и удаление дублей Nexus.

Для живого прогона скрипт обращается к уже запущенному сервису и скачивает оба отчёта через тот же API, что используется в GUI. В Bitbucket Cloud используются проекты `J4S01`–`J4S10` workspace `artifact_graph`. Docker-образы с настоящим Eclipse Temurin JRE загружены в `java4shell-fixtures` на локальном Nexus кластера `osa-nexus-e2e`. Ожидание для каждого источника — 10 находок, 8 кандидатов, 0 ошибок охвата. Пограничные проверки включают Java 17.0.5, Java 17.0.6 и Java 21.0.5.

На локальном стенде веб-интерфейс опубликован на порту 18084. Nexus REST и Docker connector доступны контейнеру через `host.docker.internal` на портах 18182 и 18184, пока работают соответствующие port-forward. При исчерпании подсетей Docker Desktop локальный `compose.override.yaml` может задать `network_mode: bridge` для сервиса `inventory`.
