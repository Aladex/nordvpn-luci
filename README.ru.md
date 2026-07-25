# NordVPN WireGuard для OpenWrt

[English](README.md) · **Русский** · [Deutsch](README.de.md)

Настройка сервиса WireGuard (NordLynx) от NordVPN на OpenWrt: одноразовый
обмен учётными данными, выбор страны/города/сервера (включая Double VPN и
Onion over VPN), автоматическая ротация, несколько параллельных VPN-инстансов,
маршрутизация трафика по сетям с kill switch (аварийное отключение) и защитой
от утечки IPv6, а также нативная страница LuCI.

> **Неофициальный проект.** Он не связан с Nord Security, не одобрен и не
> поддерживается компанией. «NordVPN» и «NordLynx» — торговые марки их
> соответствующих владельцев. Используйте свою учётную запись NordVPN и свой
> access-токен.

![Обзорная страница LuCI](docs/screenshots/overview.png)

## Архитектура

Проект поставляется в виде **двух пакетов**, чтобы VPN-сервис был полезен и без
веб-интерфейса, а приложение LuCI оставалось тонким фронтендом:

- **`nordvpn-wireguard`** — бэкенд (целевой feed `openwrt/packages`,
  `net/nordvpn-wireguard`). ucode + procd + объект rpcd/ubus. Выполняет обмен
  учётными данными, кэширование списка серверов, генерацию интерфейса/пиров
  WireGuard, проверку handshake (рукопожатия), запланированную ротацию и
  отдаёт статус в рантайме. Работает из CLI и через ubus без установленного
  LuCI.
- **`luci-app-nordvpn`** — фронтенд LuCI (целевой feed `openwrt/luci`,
  `applications/luci-app-nordvpn`). JavaScript-представление, вызывающее
  методы ubus бэкенда. Само по себе не выполняет привилегированных операций
  с файловой системой или сетевой конфигурацией.

Браузер никогда не получает ни access-токен, ни приватный ключ WireGuard.

## Структура репозитория

```
nordvpn-wireguard/                         # backend package (packages feed)
├── Makefile
├── test.sh                                # CI version smoke test
├── files/etc/config/nordvpn               # non-secret settings (owns config)
├── files/etc/init.d/nordvpn               # consolidated procd service
├── files/etc/uci-defaults/90-nordvpn-migrate
├── files/usr/bin/nordvpn-service          # uloop scheduler daemon
├── files/usr/bin/nordvpn-cache-update     # one-shot cache worker
├── files/usr/bin/nordvpn-rotate           # one-shot rotation worker
├── files/usr/share/rpcd/ucode/nordvpn.uc  # ubus object 'nordvpn'
├── files/usr/share/ucode/nordvpn/*.uc     # shared ucode modules
└── tests/                                 # offline ucode fixture/unit tests

luci-app-nordvpn/                          # LuCI frontend (luci feed)
├── Makefile
├── htdocs/luci-static/resources/view/nordvpn/overview.js
├── po/templates/nordvpn.pot
└── root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-nordvpn.json

docs/screenshots/                          # LuCI page screenshots (README)
```

## Поддерживаемые релизы

- **Основной:** текущий OpenWrt master / snapshots (использует `apk`).
- **Дополнительный:** OpenWrt 25.12, где совпадают API и зависимости.
- Более старые релизы — только через отдельно поддерживаемую downstream-сборку.

## Установка

### Из подписанного feed-репозитория пакетов (рекомендуется)

CI публикует подписанные, архитектурно-независимые пакеты для каждого релиза на
<https://aladex.github.io/nordvpn-luci/>.

**OpenWrt 24.10 (opkg):**

```sh
wget -O /etc/opkg/keys/6bf1f0b6d25ceaad \
  https://aladex.github.io/nordvpn-luci/keys/6bf1f0b6d25ceaad
echo 'src/gz nordvpn_luci https://aladex.github.io/nordvpn-luci/packages/opkg' \
  >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-nordvpn        # or just nordvpn-wireguard for headless
```

**OpenWrt snapshots / 25.x (apk):**

```sh
wget -O /etc/apk/keys/nordvpn-luci-apk.pem \
  https://aladex.github.io/nordvpn-luci/keys/nordvpn-luci-apk.pem
echo 'https://aladex.github.io/nordvpn-luci/packages/apk/packages.adb' \
  >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add luci-app-nordvpn
```

После установки выйдите из LuCI и войдите снова, затем откройте **VPN → NordVPN**.

### Из feed-репозитория пакетов / snapshot-сборки

Соберите с помощью OpenWrt SDK под свою платформу. Бэкенд — обычный пакет
packages-feed; приложение LuCI собирается внутри checkout-а `openwrt/luci`.

```bash
# backend (packages feed style)
cp -r nordvpn-wireguard "$SDK/package/nordvpn-wireguard"
cd "$SDK" && ./scripts/feeds update -a && ./scripts/feeds install -a
make defconfig
make package/nordvpn-wireguard/compile

# frontend (from an openwrt/luci checkout)
cp -r luci-app-nordvpn openwrt-luci/applications/luci-app-nordvpn
# build via the luci feed as usual
```

Установите полученные пакеты на роутер:

```bash
apk add ./nordvpn-wireguard-*.apk ./luci-app-nordvpn-*.apk   # 25.x / snapshots
# or: opkg install ./nordvpn-wireguard_*.ipk ./luci-app-nordvpn_*.ipk   # 24.10
```

Установка одного `nordvpn-wireguard` даёт рабочий CLI/сервис; добавьте
`luci-app-nordvpn` для веб-интерфейса.

## Использование

1. Откройте LuCI → **VPN → NordVPN**.
2. Нажмите **Set credentials** (Задать учётные данные) и вставьте свой
   64-символьный access-токен NordVPN. Он один раз обменивается на приватный
   ключ WireGuard и **никогда не сохраняется**.

   ![Диалог учётных данных](docs/screenshots/credentials-modal.png)

3. Выберите **Hop mode** (Режим переходов):
   - **Single hop** (Одиночный переход) — обычный VPN-сервер.
   - **Multihop** (Double VPN) — выбранная страна является страной **выхода**
     (ваш видимый IP); трафик входит через страну-партнёра, указанную в имени
     сервера («United Kingdom - Netherlands #10» входит в Великобритании и
     выходит в Нидерландах).
   - **Onion over VPN** — трафик покидает VPN-сервер через сеть Tor. Заметно
     медленнее, и некоторые сайты блокируют выходные узлы Tor. Эти серверы
     никогда не появляются в других режимах, поэтому Tor всегда является явным
     выбором.

   ![Режим Onion over VPN](docs/screenshots/onion-mode.png)

4. Выберите **Country** (Страна, обязательно), при желании **City** (Город) и
   **Server** (Сервер). Названия стран сопровождаются эмодзи-флагами (обычные
   названия на системах без глифов флагов). Оставьте City и Server в положении
   *Automatic*, чтобы ротировать внутри страны.
5. При желании включите **Automatic rotation** (Автоматическую ротацию) и
   расписание. Когда ротация активна, страница показывает конкретное время
   **Next rotation** (Следующая ротация; запланировано роутером, отображается в
   местном часовом поясе вашего браузера).

   ![Автоматическая ротация](docs/screenshots/rotation.png)

6. Нажмите **Save and reconnect** (Сохранить и переподключиться).

Получить токен можно на
<https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/> →
**Generate new token** (Сгенерировать новый токен; подойдёт бессрочный токен).

Сохранённая конфигурация и установленный туннель показываются как **разные
состояния** — страница никогда не заявляет «Connected» только потому, что
настройки были сохранены.

## Конфигурация (`/etc/config/nordvpn`)

Бэкенд владеет здесь несекретными настройками; свежая установка поставляется
**выключенной**. Одна секция `config instance` на каждый VPN-инстанс («main» —
инстанс по умолчанию, он же несёт общие настройки кэша).

```
config instance 'main'
	option enabled '0'
	option interface 'nordvpn'
	option routing_table ''
	option hop_mode 'single'          # 'multihop' (Double VPN) / 'onion' (via Tor)
	option country_code 'ee'
	option city_code 'ee-tallinn'
	option fixed_server ''            # pin a gateway; disables rotation
	option rotation_enabled '0'
	option rotation_mode 'interval'  # or 'time'
	option rotation_interval '360'   # minutes
	option rotation_time '04:30'     # HH:MM, router local time
	option verify_timeout '8'        # seconds to wait for a WG handshake
	option max_retries '10'          # candidate servers per rotation
	option auto_routing '1'          # route all LAN traffic via the VPN
	list source_network 'media'      # or: steer only these networks (see below)
	option killswitch '0'            # block steered traffic while VPN is down
	option block_ipv6 '1'            # block direct IPv6 (leak prevention)
	option vpn_dns 'off'             # off | standard | threat (NordVPN resolvers)
	option cache_dir ''              # empty = /tmp, shared by all instances
	option cache_refresh_interval '21600'   # seconds, background refresh
```

Все эти параметры редактируются со страницы LuCI (большинство — в разделе
**Advanced settings**, Расширенные настройки):

![Расширенные настройки](docs/screenshots/advanced.png)

Сгенерированный интерфейс/пир WireGuard находятся в `/etc/config/network` и
управляются бэкендом. Приватный ключ хранится там для netifd, но никогда не
появляется ни в одном ответе status/ubus.

## ubus API

Все методы принадлежат объекту `nordvpn`. Методы чтения ничего не изменяют;
секреты никогда не возвращаются.

```bash
ubus call nordvpn status            # runtime state, location, handshake age
ubus call nordvpn instances         # status of every configured VPN instance
ubus call nordvpn external_ip       # public IP as seen through the tunnel
ubus call nordvpn disconnect        # take the tunnel down, pause rotation
ubus call nordvpn clear_credentials # forget the stored WireGuard key
ubus call nordvpn locations         # cached country/city tree (+ per-city counts)
ubus call nordvpn servers '{"country":"de","city":"de-berlin","hop_mode":"single"}'
ubus call nordvpn refresh_status    # cache-refresh job progress
ubus call nordvpn set_credentials '{"token":"<64-hex-token>"}'
ubus call nordvpn apply             # rebuild the peer and bring the tunnel up
ubus call nordvpn rotate_now        # one-shot rotation
ubus call nordvpn refresh_locations # start an async server-list refresh
```

`status` различает *configured* (настроен) и *connected* (подключён):
`connected` требует handshake WireGuard свежее 3 минут, `degraded` означает,
что интерфейс поднят, но handshake устарел, а `rotation.next_run` — это epoch
следующей запланированной ротации (`null`, когда ротация не может быть
выполнена). Он также сообщает административный флаг `enabled` (выключенный
инстанс намеренно опущен, а не просто отключён) и `fixed` (сервер закреплён,
поэтому ротация выключена); страница LuCI завязывает свои кнопки действий на оба
флага — показывая единый переключатель Enable/Disable
(Включить/Выключить) и скрывая «Rotate now» (Ротировать сейчас) для
закреплённого туннеля.

### Несколько VPN-инстансов

`/etc/config/nordvpn` может содержать несколько секций
`config instance '<name>'` («main» — по умолчанию). Каждый инстанс запускает
собственный туннель на своём интерфейсе, со своими учётными данными и
расписанием ротации — например, основной маршрут через Германию и медиасеть
через Сербию. Выдавайте отдельный access-токен NordVPN на каждый инстанс:
повторное использование одного ключа из нескольких мест, по сообщениям,
приводило к блокировке ключа со стороны NordVPN. `status`, `apply`, `rotate_now`
и `set_credentials` принимают аргумент `instance` (по умолчанию `main`);
`create_instance`/`delete_instance` управляют жизненным циклом, а
`nordvpn-rotate <name>` ротирует один инстанс из CLI. Кэш списка серверов —
общий.

Страница LuCI перечисляет каждый инстанс с его состоянием, сервером и следующей
ротацией; клик по строке выбирает её, и вся форма (учётные данные, страна,
ротация, маршрутизация) применяется к выбранному инстансу. **Add instance**
(Добавить инстанс) создаёт новый (он получает интерфейс `nv_<name>`), **Delete**
(Удалить) опускает туннель и удаляет его интерфейс, помеченные объекты
файрвола и настройки; для «main» кнопка называется **Reset** (Сброс) — секция
остаётся, но каждый параметр возвращается к значению по умолчанию. Полоса
статуса показывает фактический город подключённого сервера и публичный IP,
видимый через туннель, и предлагает **Disconnect** (Отключить; туннель опущен,
ротация приостановлена до следующего подключения). Учётные данные можно удалить
без удаления инстанса.

Чтобы направить через инстанс только некоторые сети, выберите их в разделе
**Steered networks** (Направляемые сети) в его панели Traffic routing:
бэкенд поддерживает помеченные policy-правила (`in <network> lookup <table>`,
приоритет 20000) плюс prohibit-правила, работающие как kill switch по сетям
(опционально) и блокировка утечки IPv6 (по умолчанию включена) — они
срабатывают только тогда, когда таблица туннеля не может обслужить трафик.
Чтобы направляемый маршрут по умолчанию не поглощал локальные назначения,
бэкенд также зеркалирует каждую локальную подсеть IPv4 в таблицу инстанса
(подсети интерфейсов, статические маршруты и allowed-IPs ваших собственных
WireGuard-линков; ваши собственные маршруты для той же подсети всегда
побеждают). Либо продолжайте использовать свои собственные правила
policy-routing (ручной режим определяется и не трогается).

![VPN-инстансы](docs/screenshots/instances.png)

Доступ ограничен ACL `luci-app-nordvpn`: методы чтения — для сессий чтения,
методы записи — для сессий записи. Аккаунт LuCI только для чтения не может
вызвать методы записи, а сырой приватный ключ недостижим через UCI или ubus.

## Сервисы и логи

```bash
service nordvpn status
service nordvpn version        # installed version
logread -e nordvpn
```

Один демон под управлением procd (`nordvpn-service`) обновляет кэш и выполняет
запланированную ротацию, перечитывая `/etc/config/nordvpn` на каждом 30-секундном
тике; изменение конфигурации перезапускает его. Часы ротации сохраняются в
`/tmp/nordvpn_rotate_state.json`, поэтому перезапуски демона не сбрасывают
расписание и не вызывают ложную ротацию.

### Проверка серверов (apply и ротация)

Список серверов NordVPN включает мёртвые endpoint-ы, а все WireGuard-серверы в
стране используют один публичный ключ — поэтому плохой endpoint всё равно
поднимает интерфейс «up» без ошибки. Поэтому и **apply**, и **ротация**
проверяют каждого кандидата, ожидая до `verify_timeout` секунд реального
**handshake WireGuard** (`wg show latest-handshakes`), а не через пинг сквозь
туннель. Ротация всегда переходит только на **другой** сервер: текущий шлюз
исключается из набора кандидатов, поэтому ротация, о которой сообщено как об
успешной, всегда сменила сервер. Она пробует до `max_retries` перемешанных
кандидатов и, если ни один не завершил handshake, восстанавливает последний
рабочий пир, а не оставляет мёртвый туннель. Когда выбор не соответствует ни
одному серверу, кроме текущего, ротация становится no-op и сохраняет рабочий
туннель. Apply ведёт себя так же для автоматических выборов. (`max_retries` —
намеренное ограничение: воркер ротации должен завершиться заметно раньше окна
устаревания блокировки, чтобы следующий запланированный тик не мог запустить
вторую, перекрывающуюся ротацию.)

### Ротация между режимами переходов

Ротация учитывает режим переходов — она рассматривает только серверы того же
типа, что и у инстанса. Инстанс **Multihop** ротируется среди серверов Double
VPN с той же страной **выхода** (страна входа может меняться между ротациями);
инстанс **Onion over VPN** ротируется только среди onion-серверов; single-hop
никогда не смешивается ни с тем, ни с другим. Поскольку пулы Double VPN и Onion
намного меньше пула single-hop, страна — или закреплённый город — может
предоставлять лишь один сервер такого типа, и в этом случае ротировать не на
что и текущий туннель сохраняется. Onion over VPN вообще существует лишь в
нескольких странах, поэтому пара с страной, где его нет, оставляет ротацию без
кандидатов.

### Кэш списка серверов

Демон обновляет кэш автоматически: на своём первом тике после старта он
обновляет кэш, если файл на диске старше 24 ч, а затем — каждые
`cache_refresh_interval` секунд (6 ч по умолчанию). Кнопка **Refresh server
list** (Обновить список серверов) в интерфейсе запускает тот же одноразовый
воркер (`nordvpn-cache-update`) асинхронно. Записи в кэш атомарны (временный
файл + переименование), обновления сериализуются блокировкой, а неудавшееся
обновление сохраняет предыдущий рабочий кэш.

## Маршрутизация трафика и файрвол

Панель **Traffic routing** (Маршрутизация трафика) решает, как трафик достигает
туннеля. При каждом apply бэкенд сначала *определяет* текущую схему:

- **Manual** (Ручная) — существуют непомеченные маршруты/правила, ссылающиеся
  на VPN-интерфейс, или настроена таблица маршрутизации без направления
  трафика. Тогда пакет никогда не трогает маршрутизацию или файрвол; панель
  чисто информационная (с предупреждением об утечке IPv6, когда на WAN есть
  IPv6).

  ![Обнаружена ручная маршрутизация](docs/screenshots/routing-manual.png)

- **Automatic** (Автоматическая) — включён *Route all LAN traffic through the
  VPN* (Направлять весь трафик LAN через VPN; по умолчанию при свежей
  установке) и ручная схема не обнаружена. Тогда бэкенд поддерживает:
  `route_allowed_ips` на пире (netifd устанавливает маршрут по умолчанию через
  туннель и удаляет его, когда интерфейс опускается — маршрут по умолчанию для
  WAN никогда не изменяется), masquerading-зону файрвола для интерфейса и
  forwarding из зоны LAN. Дополнительные переключатели добавляют **kill
  switch** (правило REJECT LAN→WAN, чтобы клиенты LAN оставались без интернета,
  пока VPN опущен), **блокировку IPv6** (family-ipv6 REJECT LAN→WAN, включена
  по умолчанию — NordLynx внутри работает только по IPv4, поэтому прямой IPv6
  обошёл бы туннель) и **переопределение DNS** на интерфейсе: `standard`
  проталкивает обычный резолвер NordVPN (103.86.96.100 / 99.100), `threat`
  проталкивает NordVPN Threat Protection (103.86.96.96 / 99.99, блокируя
  рекламу и вредоносное ПО на уровне DNS). Оба резолвят только через туннель;
  `off` сохраняет системный/WAN-резолвер.

- **Steered** (Направляемая) — конкретные сети отмечены в разделе *Steered
  networks* (`list source_network`). Только их трафик policy-маршрутизируется в
  таблицу инстанса; собственный трафик роутера и другие сети не трогаются.
  Переключатели kill switch / IPv6 становятся prohibit-правилами по сетям,
  которые срабатывают только тогда, когда туннель не может обслужить трафик, а
  каждая локальная подсеть IPv4 зеркалируется в таблицу, чтобы связь
  VLAN-в-VLAN и локальные сервисы оставались доступными (ваши собственные
  маршруты для подсети всегда побеждают).

  ![Направляемые сети](docs/screenshots/routing-steered.png)

Всё, что создаёт автоматический режим, помечается `nordvpn_managed`; отключение
переключателя (или автоматического режима) удаляет ровно помеченные объекты и
ничего больше. Созданные пользователем зоны, forwarding-и, маршруты и правила
никогда не изменяются. Обновления со старого Lua-приложения сохраняют
`auto_routing '0'`.

### Собственные таблицы маршрутизации (ручной режим)

Задайте **Routing table** (Таблица маршрутизации; в Advanced), чтобы направить
VPN-трафик через отдельную таблицу (`ip4table`/`ip6table` на интерфейсе), затем
добавьте правила в **Network → Routing → Policy Routing**.

## Безопасность

- Access-токен обменивается на приватный ключ через анонимный pipe (curl
  читает его из конфига в `/proc/self/fd`); он никогда не появляется в argv,
  переменной окружения, временном файле или логах и никогда не сохраняется.
- Каждая внешняя команда собирается из списка argv, где каждый аргумент
  заключён в одинарные кавычки для шелла, а каждое подставляемое значение
  (имена интерфейсов, хостнеймы, расписания, пути к кэшу) сначала проверяется
  по белому списку, так что внедрить синтаксис шелла нельзя.
- Все входные данные ubus имеют фиксированную схему и проверяются по
  диапазону/формату.
- Записи в кэш атомарны (временный файл + переименование), обновления
  сериализуются блокировкой; неудавшееся обновление сохраняет последний рабочий
  кэш.

## Обновление / откат

Обновление со старого Lua-приложения `luci-app-nordvpn` запускает одноразовую
идемпотентную миграцию (`uci-defaults`), которая копирует несекретные настройки
в `/etc/config/nordvpn`, сохраняет существующий приватный ключ и активный пир,
удаляет любой сохранённый токен и убирает старые записи cron. Она не разрывает
рабочий туннель. Откат к старому Lua-пакету не поддерживается (он не читает
новую раскладку конфигурации).

## Связанные проекты

- [**NordVPN Lite**](https://nordvpn.com/blog/nordvpn-for-openwrt-routers/) —
  официальный, намеренно минималистичный клиент для OpenWrt: одно подключение
  NordLynx, настройка через CLI/базовый LuCI. Этот проект — альтернатива для
  продвинутых пользователей: несколько параллельных инстансов с отдельными
  учётными данными, направление трафика по сетям с kill switch и защитой от
  утечки IPv6, запланированная ротация, проверенная handshake WireGuard, Double
  VPN / Onion over VPN как явные режимы и приоритет обнаружения ради
  безопасности вокруг вручную собранной маршрутизации.
- [**NordVPN-Easy-OpenWrt**](https://github.com/tis24dev/NordVPN-Easy-OpenWrt)
  — основанная на shell community-интеграция с проверками здоровья и
  восстановлением. Этот проект вместо этого использует нативные ucode/rpcd/procd
  с offline-набором тестов и покрывает мульти-инстансность, направление трафика
  и ротацию.
- Генераторы конфигов (например,
  [NordVPN-WireGuard-Config-Generator](https://github.com/mustafachyi/NordVPN-WireGuard-Config-Generator))
  создают статические `.conf`-файлы и оставляют маршрутизацию, ротацию и
  восстановление на вас.

## Разработка

Offline-тесты ucode (не нужны ни аккаунт, ни сеть):

```bash
# with ucode + ucode-mod-fs + ucode-mod-math available
sh nordvpn-wireguard/tests/run.sh
```

CI выполняет статические проверки shell/JSON, LuCI ESLint для JS-представления,
тесты ucode и сборку бэкенда под snapshot-SDK. См. `.github/workflows/build.yml`.

## Лицензия

[0BSD](LICENSE) — делайте с этим что угодно.
