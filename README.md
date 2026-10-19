# mutekizu

Локальный обход **узкого класса** DPI-фильтрации для TCP/TLS. Два независимых
режима: разбиение TLS ClientHello по SNI (NFQUEUE) и MSS-clamp в SYN-ACK
(nftables, без userspace в data path). Не VPN, не прокси, не туннель. Соединение идёт напрямую к запрошенному серверу, публичный
IP не меняется, TLS остаётся сквозным (сертификаты не подменяются, CA не
устанавливается).

Реализация: C++20, nftables, libnetfilter_queue. Ядро 7.2, nftables 1.1.7,
libnetfilter_queue 1.0.5 — проверено на CachyOS x86_64.

---

## 1. Что именно решается, а что нет

Локальная обработка без посредника может влиять только на то, что видно в
**собственных исходящих пакетах**. Она не может «переписать» решение сети.

| Модель фильтра | Локально решается? | Почему |
|---|---|---|
| Фильтрация DNS (подмена/подмена NXDOMAIN) | Нет (этим инструментом) | Нужен другой DNS-резолвер; mutekizu не трогает системный DNS |
| Блокировка по видимым признакам TLS (SNI в ClientHello) | **Да, частично** | Разбиение ClientHello на TCP-сегменты ломает наивный однопакетный анализ |
| Блокировка/throttling по IP и подсетям | Нет | Смена IP означает посредника; здесь его нет |
| Запрет UDP/QUIC | Нет для QUIC | Инструмент работает только с TCP; QUIC не маскируется и не отключается |
| Разрешительные списки (только whitelisted) | Нет | Нечего обходить: соединение к запрещённому адресу не устанавливается |
| Нет внешней связности | Нет | Локальная манипуляция не создаёт маршрут |

Дополнительно механизм **не помогает**, если DPI:

* собирает TCP-поток и корректно реассемблирует ClientHello;
* использует ECH (Encrypted ClientHello) — SNI вообще не виден, разбивать нечего;
* блокирует по IP/ASN или по поведению, а не по SNI;
* рвёт уже установленный медиапоток (mid-stream throttling). zapret-подобные
  инструменты тоже не лечат это: они влияют на начало соединения.

Инструмент **не делает трафик невидимым**: адреса, порты, SNI во втором
сегменте, размеры и тайминги видны. Это не средство анонимности.

---

## 2. Выбранный механизм

Сравнение двух вариантов:

| | NFQUEUE + правка пакетов | Локальный прозрачный TCP-релей |
|---|---|---|
| Кто устанавливает соединение | приложение (ядро) | демон, напрямую к тому же dst |
| Видимость для приложения | полностью прозрачно | нужен nftables REDIRECT, меняется src-порт |
| Управление сегментацией | вручную: seq/ack/checksum/options | ядро; но `write()` ≠ сегмент, нужен ACK-paced writes |
| GSO/TSO/PMTUD/retransmit | нужно учитывать | делает ядро |
| Выборочность по SNI | да, пакет уже в userspace | после accept, но через релей идут все redirected потоки |
| Риск для невыбранного трафика | минимальный (ACCEPT) | выше (весь TCP/443 через демон) |

Выбран **NFQUEUE + переразбиение ClientHello**:

* nftables отправляет в очередь только первые `inspect_packets` пакетов
  original-направления для TCP/443 (`ct original packets 0-10`);
* демон разбирает TLS строго по длинам (без поиска строк), достаёт SNI;
* если SNI в списке, payload текущего TCP-пакета переразбивается на сегменты:
  первый заканчивается **внутри имени хоста**, остальное — кусками ≤ `mss`;
* сегменты отправляются через `SOCK_RAW`/`IP_HDRINCL` с корректными
  seq/ack/флагами/TCP-опциями/pseudo-header checksum; исходный пакет получает
  verdict `DROP`;
* пакеты демона помечаются `SO_MARK`, и правило nftables их не перехватывает —
  бесконечного цикла нет.

Почему сервер получает корректный поток: последовательные номера, ACK,
window, TCP timestamps и прочие опции копируются из исходного заголовка;
границы сегментов не меняют байтовый поток; при потере сегмента ядро
ретранслирует данные из своего send-queue как обычно. При ошибке raw-отправки
демон **не дропает** оригинал (fail-open), возможны только дубликаты с теми же
seq/байтами, что безвредно для TCP.

### Про сегментацию и `write()`

Отдельные `write()` приложения не гарантируют отдельные TCP-сегменты — ядро
может склеить их (Nagle, GSO/TSO). Поэтому здесь сегментация делается не
«надеждой на write()», а явной сборкой IP/TCP-пакетов. Если NFQUEUE всё же
отдал GSO-суперпакет, весь его payload переразбивается на сегменты ≤ `mss`
(по умолчанию 1200), а не отправляется одним куском.

### Что остаётся видимым

* IP-адреса и порты, весь дальнейший (не TLS-handshake) трафик;
* вторая часть SNI в следующем сегменте (и SNI целиком, если DPI собирает поток);
* характерная картина: два сегмента на ClientHello, размер первого ≈ позиции
  разрыва; это эвристический признак для активного DPI.

### Мульти-разрыв SNI

Один разрыв `split_delta` внутри короткого SNI обходит DPI, который ищет полное
имя в одном сегменте. Для длинного имени с заблокированным суффиксом
(`aaaa…bbbb…test.example`) разрыв в начале оставляет `test.example` целиком во
втором сегменте. `split_stride=N` (`>0`) добавляет границы каждые N байт по
всему SNI (до `split_max`); это режет и суффикс. Цена — больше сегментов.
Проверено в арене: `split_stride=4` обходит L2 на длинном SNI, но не L3+.

`split_gap_ms=N` (0..100, experimental) добавляет паузу между raw-сегментами.
В лаборатории gap=5 не ломает TLS и сохраняет обход L1/L2; на реальном пути
пауза может изменить то, как DPI склеивает/не склеивает сегменты. Это
эксперимент, а не гарантия; пауза добавляет задержку на каждую границу.
В реальном тесте (x.com/YouTube/gateway, 5 попыток) gap 0 дал 2/15, а gap 2/5/10
— 0/15; пользы от паузы не обнаружено, значение по умолчанию 0.

### Режим MSS-clamp (опция, отдельно от SNI)

`mss_clamp=true` добавляет независимое правило в `input`:

```
meta l4proto tcp ct direction reply ct original ip daddr @mss4 \
  ct original proto-dst { 443 } tcp flags & (syn|ack|rst|fin) == (syn|ack) \
  tcp option maxseg size > 96 counter tcp option maxseg size set 96
```

Это меняет MSS в **ответном SYN-ACK**, то есть ограничивает размер сегментов,
которые клиент отправляет серверу (включая ClientHello). Сервер и TLS не
трогаются, userspace в data path отсутствует.

* Цели — **явные IP** из `mss_targets_file` (IPv4/IPv6, без CIDR и имён).
  Выбор по домену здесь невозможен; общий IP/CDN означает все соединения к нему.
* Эффект — на весь upload-поток соединения (download не затронут). `mss_value`
  меньше типичного → больше пакетов/ACK, ниже upload throughput.
* Работает и без видимого SNI (в отличие от splitter'а), но грубее по выбору.
* Правило ничего не дропает: при падении демона оно остаётся и продолжает
  ограничивать MSS; `rules remove`/`ExecStopPost` его убирают. Соединения при
  этом не рвутся.
* `split_enabled=false` + `mss_clamp=true` — режим без NFQUEUE и CAP_NET_RAW
  (в unit capability всё равно перечислена; это безвредно).

### Совместимость

* Поддерживается первый TLS-рекорд с ClientHello. Если ClientHello разнесён по
  нескольким TLS-записям или SNI отсутствует (PSK/ECH), инструмент не вмешивается.
* IPv4 и IPv6 (без extension headers). IPv6-фрагменты и extension headers
  пропускаются без обработки.
* TCP-фрагментация на IP-уровне не поддерживается (пакеты с MF/offset
  пропускаются).
* При MTU меньше 1280 IPv6-сегменты могут не пройти; `mss` настраивается.
* MSS-режим видит только локально инициированные TCP-соединения (input hook);
  forward/контейнерные namespace не охватываются.
* «Хитрые» middlebox, чувствительные к переупорядочиванию/дубликатам, в
  редких случаях могут ухудшить соединение. Отключается одной командой.

---

## 3. Архитектура

```
src/config.*          разбор key=value, домены, валидация
src/tls_clienthello.* строгий парсер TLS ClientHello и SNI (границы/длины)
src/strategy.*        выбор: не трогать / split; позиция внутри SNI
src/netpacket.*       разбор IPv4/IPv6/TCP, сборка сегментов, checksums
src/nfq_engine.*      NFQUEUE, flow-таблица, ретрансмиссии, оценки
src/nft_rules.*       только своя таблица inet mutekizu, nft -f, dry-run
src/process.*         fork/exec без shell, таймауты
src/doctor.*          read-only диагностика
src/main.cpp          CLI, pidfile, сигналы, жизненный цикл
tests/                unit + изолированный netns-стенд + модель DPI
```

nftables-правило (единственное, что создаётся):

```
table inet mutekizu {
  chain output {
    type filter hook output priority -150; policy accept;
    meta mark != 0x44495054 tcp dport 443 ct original packets 0-10 \
      queue num 2000 bypass comment "mutekizu"
  }
}
```

* `bypass` — если демон не слушает очередь, пакеты идут дальше без обработки.
* `meta mark != ...` — исключение собственных raw-пакетов.
* `ct original packets 0-10` — только начало соединения.
* Таблица помечена `comment "mutekizu-v1"`; перед удалением/заменой демон
  проверяет владельца. Чужая таблица с тем же именем не трогается.
* Демон **никогда** не делает `flush ruleset` и не трогает чужие таблицы.
  `rules remove` удаляет только собственную таблицу.
* Повторный запуск блокируется flock на pidfile (плюс проверка PID), поэтому
  два экземпляра не конкурируют за очередь.

Fail-open: при остановке/падении демона трафик продолжает идти напрямую без
обработки. Доступность заблокированных ресурсов при этом не гарантируется.
При переполнении очереди включается `NFQA_CFG_F_FAIL_OPEN` (пакет пропускается),
плюс `queue ... bypass` для случая «нет слушателя».

Права: `CAP_NET_ADMIN` (nftables/netlink + NFQUEUE) и `CAP_NET_RAW` (raw IP).
Юнит запускает демон отдельным пользователем `mutekizu` с ambient capabilities.

---

## 4. Сборка и установка (CachyOS/Arch)

Зависимости:

```bash
sudo pacman -S --needed base-devel cmake pkgconf nftables libnetfilter_queue openssl
```

`libnetfilter_queue` в Arch уже содержит заголовки. `openssl` нужен только для
лабораторных сертификатов.

```bash
cd ~/mutekizu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Установка (не включает и не запускает службу автоматически):

```bash
sudo ./scripts/install.sh
```

Проверка **без изменений**:

```bash
mutekizu doctor
mutekizu --dry-run run
```

Запуск:

```bash
sudo systemctl enable --now mutekizu
journalctl -u mutekizu -f
```

Остановка/откат:

```bash
sudo systemctl disable --now mutekizu
sudo mutekizu rules remove        # идемпотентно; удаляет только нашу таблицу
sudo ./scripts/uninstall.sh         # --purge удалит /etc/mutekizu
```

---

## 5. Команды

```
mutekizu [-c PATH] run [--dry-run]
mutekizu doctor
mutekizu status
mutekizu validate
mutekizu rules apply|remove|show [--dry-run]
```

* `doctor` — ядро, nft, модули, capabilities, конфликт номера очереди, fwmark
  в `ip rule`, MTU интерфейсов, IPv6, конфиг, цели MSS. Ничего не меняет.
  Запущенный от пользователя `doctor` честно показывает, что у **этого
  процесса** нет CAP_*; это не значит, что служба работает без прав. Для
  полной проверки с capabilities службы: `./scripts/doctor-service.sh`
  (transient systemd unit, без root-GUI).
* `run --dry-run` — печатает точный ruleset и команду; nftables не трогает
  (проверка синтаксиса требует CAP_NET_ADMIN; без прав она пропускается).
* `status` — pidfile и наличие только нашей таблицы.
* `validate` — конфиг + домены + ruleset.

Конфиг: `/etc/mutekizu/mutekizu.conf`; домены:
`/etc/mutekizu/domains.txt` (запись `example.com` покрывает сам домен и
поддомены). Совпадение идёт по SNI, а не по IP: при общем IP/CDN, ECH или
отсутствии SNI точная привязка невозможна, и инструмент просто не вмешивается.

---

## 6. Проверка

### Unit

`tests/unit_tls.cpp` (ctest): строгий разбор ClientHello, неполные данные,
не-TLS запись, слишком большой record, точное/поддоменное совпадение,
позиция разрыва строго внутри SNI.

### Изолированный стенд

```bash
unshare -rn ./tests/run_netns.sh
```

Стенд создаёт два network namespace, veth (IPv4 10.0.0.0/24 и IPv6 fd00::/64),
TLS-сервер с проверяемым сертификатом, клиент с `check_hostname`, и «наивный
DPI» (`dpi-model`, отдельная NFQUEUE): он дропает любой **одиночный** TCP
payload, содержащий полный SNI. Это модель stateless DPI, не реальный ТСПУ.

Результат последнего прогона (28 проверок, 0 провалов):

* базовый TLS IPv4/IPv6 без инструмента — OK;
* «наивный DPI» (требует **полный** ClientHello в одном TCP payload) ломает
  handshake; для этого клиент использует X25519, чтобы hello помещался в сегмент;
* mutekizu + DPI: IPv4/IPv6, 256 KiB данных, digest совпадает;
* нецелевой SNI не трогается (DPI его по-прежнему блокирует);
* MTU 1280 и 9000, потеря 5% (netem), длинный SNI, разнесённый по сегментам;
* SIGKILL: таблица остаётся, трафик не теряется (bypass), рестарт снова
  перехватывает; чужая nftables-таблица сохраняется;
* чужая таблица с именем `mutekizu` не удаляется (owner-check);
* MSS-clamp: выбранные IPv4/IPv6 получают mss=84 (≤96), невыбранные — 1448/1428;
  после stop MSS возвращается, stale-правила после SIGKILL переживают падение
  и убираются `rules remove`; TLS с clamped MSS остаётся целым;
* benchmark 10 подключений × 64 KiB: 490 ms без инструмента, 501 ms с ним;
  RSS демона ~5.2 MiB; очередь `max_queue_len=1`: 6/6 соединений (fail-open),
  демон жив.

Важно: успех против этой модели **не доказывает** обход реального ТСПУ.
Реальная сеть может реассемблировать поток, применять ECH, IP-блокировки или
mid-stream shaping.

### Что проверить на реальной машине

1. `mutekizu doctor` — нет ли конфликта queue/mark с zapret (у zapret по
   умолчанию queue 200, mark 0x40000000; здесь 2000 и 0x44495054).
2. `mutekizu --dry-run run` — глазами проверить ruleset.
3. Запустить службу и сравнить: успешность TLS-соединений, задержку, скорость,
   CPU/RSS до/после. Смотреть `journalctl -u mutekizu`.
4. При проблемах — `systemctl stop mutekizu`; правила удаляются, трафик идёт
   напрямую.
5. Убедиться, что выбранные домены действительно блокируются именно по SNI:
   если соединение не устанавливается вообще (IP/allowlist), инструмент не поможет.

---

## 7. Источники

* nftables wiki и `man nft` (raw payload, conntrack, queue): <https://wiki.nftables.org/>
* libnetfilter_queue / NFQUEUE: <https://www.netfilter.org/projects/libnetfilter_queue/>
* kernel docs, nfnetlink_queue: <https://docs.kernel.org/networking/netfilter/nfnetlink_queue.html>
* RFC 9293 (TCP), RFC 8446 (TLS 1.3), RFC 6066 (SNI)
* zapret (MIT, bol-van) — исследование стратегий разделения/десинка;
  код не копировался: <https://github.com/bol-van/zapret>
* GoodbyeDPI — исследование Windows-подхода; в Linux не переносился:
  <https://github.com/ValdikSS/GoodbyeDPI>

Лицензия проекта: MIT (см. `LICENSE`).

---

## 8. Примечания

* `rules apply` без запущенного `mutekizu run` не фильтрует трафик: правило
  содержит `bypass`, поэтому пакеты проходят без обработки. Это сделано
  намеренно (fail-open).
* Очередь и mark по умолчанию: `2000` и `0x44495054`. Если они конфликтуют с
  другим инструментом, `doctor` сообщит; измените `queue_num`/`fwmark` в
  конфиге.
* Демон не пишет содержимое соединений. `log_sni=true` (по умолчанию выключен)
  пишет только совпавший hostname в journal — включайте осознанно.


---

## 9. GUI (Qt 6) — Mutekizu

Отдельный GUI `gui/` на Qt 6 Quick/QML (Material), Wayland-native, без трея.
Отображаемое имя — **Mutekizu**; технические имена (`mutekizu`, `mutekizu.service`,
`/etc/mutekizu`, helper) сохранены для совместимости.
Он не меняет сетевой движок и не генерирует второй nftables ruleset.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMUTEKIZU_GUI=ON
cmake --build build -j"$(nproc)"
./build/gui/mutekizu-gui --demo     # mock, никаких изменений системы
./build/gui/mutekizu-gui            # реальный backend
```

Скриншоты и отчёт: `gui/REPORT.md`, `gui/screenshots/`.

* Служба: systemd D-Bus + Polkit. GUI работает обычным пользователем, без
  CAP_NET_ADMIN/CAP_NET_RAW и без sudo.
* Запись `/etc/mutekizu`: узкий helper через `pkexec`; фиксированные файлы,
  JSON, проверка доменов/IP, symlink-защита, backup/rollback, не setuid.
* Без helper запись отклоняется; небезопасного fallback нет.
* Остановка/применение: проверка, diff, обнаружение внешних изменений,
  перезапуск через D-Bus, фактическая проверка состояния.
* Установка только GUI: `sudo gui/install-gui.sh`; удаление:
  `sudo gui/uninstall-gui.sh`. Движок/служба/конфиг не удаляются.
* Движок и service unit устанавливаются отдельно (`scripts/install.sh`).
* Закрытие окна GUI не останавливает службу; автозапуск не включается.
* В этой среде service/helper не установлены, поэтому реальные
  start/stop/apply и Polkit-авторизация помечены в отчёте как непроверенные.

`split_gap_ms` в GUI явно помечен экспериментальным; `mss` (размер куска)
отделён от MSS-clamp; multi-split предупреждает о нагрузке.


---

## 10. Дефолтная конфигурация

В репозитории по умолчанию:

* `split_enabled=true`, multi-split: `split_delta=4`, `split_stride=4`,
  `split_max=64`, `split_gap_ms=0`;
* `split_disorder=true`, `fake_enabled=true`, `fake_sni=www.microsoft.com`,
  `fake_ttl=3`, `fake_repeats=3`;
* `seqovl_enabled=true`, `seqovl_bytes=646`, `seqovl_repeats=1`;
* `udp_fake_enabled=true`, `udp_fake_ttl=4`, `udp_fake_repeats=5`
  (Discord RTC/voice STUN);
* `mss_clamp=false` (MSS по IP — отдельная опция, по умолчанию выключена);
* `mss=1200` (размер куска, не MSS-clamp), `inspect_packets=10`;
* `ports=443,8080,80,83`, IPv4 only, `queue_num=2000`,
  `fwmark=0x44495054`;
* `profiles_file=/etc/mutekizu/profiles.conf` — необязательные
  per-domain профили (раздел 14);
* `log_level=info`, `log_sni=false`;
* домены — 87 записей: 44 из `/opt/zapret/hostlists/list-general-user.txt`
  (Instagram/Facebook/Threads, Tor, Proton, Telegram web/CDN, Brave, X/Twitter),
  YouTube/Google video (youtube.com, googlevideo.com, ytimg, youtubei и др.)
  и 24 Discord-домена из `list-general.txt` (discord.com, gateway.discord.gg,
  cdn.discordapp.com, discord.gg, media и др.).
  Это список SNI-целей, не DNS; Telegram Desktop MTProto, IP-блокировки,
  DNS-подмена и QUIC им не решаются.
* IP-цели для MSS-clamp — `config/mss_targets.txt`: 250 явных адресов
  (162 IPv4 + 88 IPv6), разрешённых из этих доменов через DoH. `mss_clamp=false`
  по умолчанию, поэтому список пока неактивен; включите MSS-clamp в GUI или
  конфиге, если он вам действительно нужен.
* Обновить IP-снимок: `./scripts/update-mss-targets.py`. Адреса CDN меняются,
  а общий IP может затрагивать несколько сайтов; MSS влияет на весь upload.
  Не для всех доменов нашлись A/AAAA при генерации — список можно дополнить.

Применить эти дефолты на уже установленной системе (с бэкапом
`/etc/mutekizu/backup-*`, переустановкой GUI, enable/start службы):

```bash
sudo ~/mutekizu/scripts/install-all.sh --reset-config
```

Без `--reset-config` существующие `/etc/mutekizu/*` сохраняются, новые
примеры кладутся рядом как `.new`.


---

## 11. Автоопределение заблокированных SNI

`auto_discover=true` по умолчанию. Для SNI, которого нет ни в списке, ни в
авто-списке, движок один раз открывает **прямое** TCP/TLS-соединение к тому же
серверу (без split; сокет помечен `SO_MARK`, поэтому не попадает в очередь).
Если TLS-ответа нет за `auto_probe_timeout_ms`, SNI запоминается в
`/var/lib/mutekizu/auto-domains.txt` (0600, каталог 0700) и **следующее**
соединение к нему уже разрывается. Список переживает перезапуск службы.
Он намеренно не показывается в GUI: это фактически история посещённых
заблокированных доменов; файл доступен только службе/root.

Ограничения: `auto_probe_max` одновременных проверок (4), `auto_domain_limit`
(4096), повторная проверка домена не чаще `auto_probe_interval_s` (600 с).
Проверка — это дополнительное соединение; минимальный ClientHello может
получить отказ сервера, не связанный с фильтром, поэтому возможны ложные
срабатывания. Выключить: `auto_discover=false` в GUI/конфиге. DNS-подмена,
IP-блокировки и QUIC автоопределением не решаются.

В лаборатории проверено: неизвестный `test.example` блокируется, попадает в
auto-list, следующее соединение разрывается и проходит (31/31 проверок стенда).

---

## 12. Автозапуск и привилегии

Служба `mutekizu.service` включена в `multi-user.target` и работает с
`Restart=always`: после падения/перезагрузки поднимается сама. Она запускается
не от UID 0, а от отдельного пользователя `mutekizu` с ровно двумя
capabilities — `CAP_NET_ADMIN` и `CAP_NET_RAW`. Этого достаточно для nftables,
NFQUEUE и raw-сокетов; полный root движку не нужен и только увеличил бы
последствия ошибки в разборе пакетов.

GUI **не запускается от root**. Причины: Qt/Wayland-root не имеет доступа к
сессии пользователя (XDG_RUNTIME_DIR/WAYLAND_DISPLAY), получает чужие
root-owned конфиги/кэш и превращает любую ошибку GUI в root-код. Вместо этого:

* обычный запуск: `mutekizu-gui` (или иконка Mutekizu);
* старт/стоп/рестарт — systemd D-Bus + Polkit;
* запись `/etc/mutekizu/*` — только узкий root-owned helper через pkexec.

Если нужен автозапуск окна при входе:

```bash
install -D -m 0644 ~/mutekizu/gui/autostart/mutekizu.desktop \
    ~/.config/autostart/mutekizu.desktop
```

Если нужно управлять службой и применять настройки **без запроса пароля**
(только для пользователей `wheel`/`sudo`, которые и так могут стать root):

```bash
sudo ~/mutekizu/scripts/install-all.sh --polkit-noauth
```

Правило разрешает ровно `mutekizu.service` и ровно
`/usr/libexec/mutekizu-config-helper`, не произвольный systemctl/pkexec.
По умолчанию правило не устанавливается. Запускать GUI через `sudo`/`pkexec`
не следует — это не поддерживаемый и небезопасный путь.

---

## 13. Продвинутый TCP-desync (в духе zapret, опционально)

В поставляемом дефолте включены:

* `split_disorder=true` — сегменты ClientHello уходят в обратном порядке.
* `fake_enabled=true` — перед настоящими сегментами отправляются
  `fake_repeats` копий ClientHello с низким TTL и SNI `fake_sni`
  (по умолчанию `www.microsoft.com`).
* `seqovl_enabled=true` — один или несколько fake-сегментов с отрицательным
  перекрытием sequence (`seqovl_bytes=646`) и fake ClientHello, чтобы
  on-path DPI собирал другой поток. Число повторов — `seqovl_repeats`.
* `udp_fake_enabled=true` — low-TTL fake UDP на портах Discord RTC
  `19294-19344`, `50000-50100` и UDP/443. TTL — `udp_fake_ttl=4`,
  число повторов — `udp_fake_repeats=5`. `udp_fake_type` задаёт `stun`,
  `quic`, `discord` (RTP) или `random`.
* `reply_observe=true` — отдельная input-цепочка и NFQUEUE
  (`reply_queue_num=2001`) на первые `reply_inspect_packets` ответов сервера;
  TLS ServerHello там — точный сигнал успеха для автоподбора профилей.
* Fooling для fake: `fake_bad_checksum`, `fake_seq_offset`, `fake_timestamp`.
  Меняют только low-TTL fake, реальные сегменты не трогают.

Дополнительно можно включить:

* `split_multidisorder=true` — порядок «снаружи внутрь»: последний, первый,
  предпоследний и так далее;
* `split_jitter_ms=0..50` — случайная дополнительная пауза между сегментами.

Стенд проверяет `split_disorder` и `split_multidisorder` с TLS integrity
128 KiB — **38/38 проверок** (disorder, multidisorder, profiles, auto-profile). На реальном пути Discord проверен поставляемый
дефолт: gateway `READY`, голос `RTC_CONNECTED`. В двухnetns-стенде нет
прыжка, где успевает истечь низкий TTL, поэтому fake/seqovl/UDP fake там не
проверяются; если сеть их не принимает, отключай опцию по отдельности.

### IP-фрагментация для Telegram

`ip_frag_enabled=true` включает отдельную NFQUEUE `2002` и nft-set с
Telegram-подсетями из `ip_frag_targets.txt`. Для TCP-портов `80,443,5222`
исходящий IP-пакет режется на IPv4/IPv6-фрагменты; TCP checksum
пересчитывается. Это нужно для MTProto, у которого нет SNI.

Профиль `[telegram]` в `profiles.conf` задаёт split/fake для Telegram
TLS-доменов; IP-фрагментация работает по IP и не зависит от SNI. Размер
фрагмента — `ip_frag_size=512`, первые пакеты — `ip_frag_inspect_packets`.

Стенд проверяет IPv4 и IPv6 фрагментацию с TLS integrity — **38/38 проверок**.

Если Telegram остаётся в `SYN-SENT` (нет SYN-ACK даже при выключенном
Mutekizu и включённом zapret), это блокировка DC-IP на уровне L3/L4, а не
DPI-склейка. IP-фрагментация не создаёт маршрут и здесь не поможет; нужен
MTProxy/SOCKS5 или другой маршрут. Фрагментировать сам SYN мы не пытаемся:
контрольные пакеты проходят без изменений, фрагментируются только данные.

Осталось нереализованным: INET_DIAG/conntrack health и eBPF/XDP fast path.
TCP MD5/AO-фулинг и hostlist-движок тоже пока нет.

---

## 14. Профили по доменам

Глобальные значения остаются в `mutekizu.conf`, а необязательный
`/etc/mutekizu/profiles.conf` позволяет переопределить стратегию для
конкретных доменов:

```ini
[discord]
domains = discord.com, discord.gg, gateway.discord.gg
split_disorder = true
fake_enabled = true
fake_sni = www.microsoft.com
seqovl_enabled = true
seqovl_bytes = 646

[youtube]
domains = youtube.com, googlevideo.com, ytimg.com
split_delta = 4
split_stride = 4
split_disorder = false
fake_enabled = false
```

Правила:

* секции читаются сверху вниз, побеждает **первое** совпадение домена
  (включая поддомены);
* в профиле можно задать только те ключи, которые отличаются от глобальных;
* профиль может включить домен, которого нет в `domains.txt`;
* поддерживаются все TCP-ключи split/fake/seqovl, включая
  `split_multidisorder`, `split_data`, `split_jitter_ms`;
* `interfaces = wlan0, wwan0` ограничивает профиль сетевым интерфейсом;
  без этого ключа профиль подходит для любого интерфейса (SSID пока нет);
* наследования профилей пока нет; общие значения берутся из `mutekizu.conf`;
* изменения профилей применяются после restart службы.

Путь задаётся ключом `profiles_file=` (по умолчанию
`/etc/mutekizu/profiles.conf`). Файл создаётся установщиком с примерами в
комментариях; если его нет, работают глобальные настройки.

В GUI есть страница **«Профили»**: редактор `profiles.conf` с подсветкой
ошибок, кнопками «Проверить», «Применить», «Откатить» и шаблонами Discord /
YouTube. Проверка идёт через тот же `mutekizu validate`, запись — через
PKEXEC-helper и атомарную замену файла.

### Автоподбор профилей

Если несколько секций `profiles.conf` покрывают один и тот же домен, включается
автоподбор (`auto_profile=true`):

* первая попытка использует первый подходящий профиль;
* если клиент повторно открыл соединение к тому же SNI в течение
  `auto_retry_window_s` и предыдущая попытка не дошла до данных после
  ClientHello, движок переключается на следующий подходящий профиль;
* успехом считается любой payload клиента после конца ClientHello (TLS
  Finished, HTTP, WebSocket). Успешный профиль остаётся текущим.

Пример двух вариантов для Discord:

```ini
[discord-safe]
domains = discord.com, discord.gg, gateway.discord.gg
split_disorder = true
fake_enabled = false
seqovl_enabled = false

[discord-aggressive]
domains = discord.com, discord.gg, gateway.discord.gg
split_disorder = true
fake_enabled = true
fake_sni = www.microsoft.com
seqovl_enabled = true
seqovl_bytes = 646
```

Если профиль один, автоподбор не вмешивается. Ограничение: успех определяется
по последующему трафику клиента, без отдельного наблюдения ServerHello;
параллельные соединения к одному SNI могут вызвать лишнюю ротацию. Для
предсказуемости задавай `auto_retry_window_s` больше типичного интервала
повторной попытки приложения.
