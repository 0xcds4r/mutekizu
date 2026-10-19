# mutekizu vs synthetic DPI ladder — arena report

Дата: 2026-10-20. Все результаты получены в **изолированном стенде** внутри
непривилегированного user+network namespace. Firewall, DNS и QUIC рабочей
машины не изменялись. Это отчёт о лабораторных моделях, **не** об измерении
реального ТСПУ.

## 1. Среда и права

* `Linux 7.2.9-2-cachyos x86_64`, `nftables 1.1.7`, `libnetfilter_queue 1.0.5`,
  `g++ 16.2.1`, `Python 3.14`, `openssl`.
* Запуск: `unshare -rn ...`; `CapEff=0x1ffffffffff` внутри userns, проверены
  именно `CAP_NET_ADMIN` (bit 12) и `CAP_NET_RAW` (bit 13), а не только UID 0.
* Топология (3 netns, veth):
  `client 10.90.1.2/fd90:1::2 → mid 10.90.1.1/10.90.2.1 → server 10.90.2.2/fd90:2::2`.
  DPI (`dpi-ladder`) стоит в `forward` middlebox; mutekizu — в клиенте.
* Сервер: локальный TLS echo с проверяемым lab-CA и SAN; клиент проверяет
  сертификат и имя. Целостность данных — SHA-256.
* Offloads на veth по умолчанию выключены для воспроизводимости; отдельный
  прогон — с TSO/GSO/GRO on.

## 2. Модели DPI (лестница)

| Уровень | Что делает | Упрощения / память | Ложные срабатывания |
|---|---|---|---|
| L1 | Блокирует, если **полный TLS record ClientHello** оказался в одном TCP payload | Нет сборки TCP; state 0; большой PQ-hello естественно не блокируется | Нет (точный SNI/суффикс) |
| L2 | Ищет literal `test.example` в одном TCP payload | Нет сборки TCP; state 0 | Может найти строку в не-TLS данных (в стенде только TLS) |
| L3 | Политика на **первый data-сегмент**: если он начинается с TLS handshake и ClientHello неполный — drop | Нет сборки; агрессивная политика «неполный = подозрительный» | Легитимная фрагментация (MSS, большой hello при малом MTU) блокируется |
| L4 | Сборка TCP по seq: перестановки, дубликаты, retransmission, overlap (first-received wins), затем разбор TLS/SNI | Буфер 64 KiB на поток, 4096 потоков; переполнение → **block** (не bypass) | Нет для точного SNI |
| L5 | L4 + требуется полный TLS record; malformed/oversized TLS-looking → block | То же; строгая политика | Может блокировать повреждённые/нестандартные hello |

L4/L5 — ключевые модели: они восстанавливают **тот же байтовый поток**, который
получает сервер.

## 3. Стратегии anti-DPI (все реализованы в утилите)

* `none` — baseline.
* `split_d1/d4/d8` — один разрыв внутри SNI (`split_delta`).
* `mss96` / `mss136` — MSS-clamp в SYN-ACK для явных IP (`mss_value`).
* `split4_mss136` — оба механизма.
* `split_multi` — несколько границ внутри SNI (`split_stride=4`, до 64 границ).
  Добавлено после раунда 1: один разрыв в начале длинного SNI не разрывает
  заблокированный суффикс `test.example` в конце имени.

## 4. Раунд 1: основной матрикс (tuning)

`X25519`, короткий SNI `test.example`, IPv4 (IPv6 дал идентичные результаты),
один прогон на клетку. `B` = DPI заблокировал, `P` = соединение прошло (TLS +
имя + SHA-256 OK). Разрешённый SNI `other.example` прошёл везде, кроме явно
указанных false positive.

| DPI | none | split_d1 | split_d4 | split_d8 | mss96 | mss136 | split4+mss136 |
|---|---|---|---|---|---|---|---|
| L1 | B | **P** | **P** | **P** | **P** | **P** | **P** |
| L2 | B | **P** | **P** | **P** | B | B | **P** |
| L3 | B | B | B | B | B¹ | B¹ | B¹ |
| L4 | B | B | B | B | B | B | B |
| L5 | B | B | B | B | B | B | B |

¹ `mss96/mss136/split4_mss136` при L3 дают **false positive**: разрешённый
`other.example` тоже фрагментирован MSS и попадает под политику «неполный
ClientHello → drop».

Полный журнал: `results/arena.jsonl` (246 записей), сводка:
`results/summary.md`.

### Статистика DPI-моделей

| уровень | packets | dropped | flows | overflow_blocks | parse_errors |
|---|---|---|---|---|---|
| L1 | 2307 | 12 | 0 | 0 | 0 |
| L2 | 1659 | 44 | 0 | 0 | 0 |
| L3 | 485 | 255 | 36 | 0 | 0 |
| L4 | 1383 | 141 | 48 | 0 | 0 |
| L5 | 1415 | 113 | 42 | 0 | 0 |

## 5. Раунд 2: независимая проверка и улучшение

Validation: TLS 1.3 PQ ClientHello (`curve=default`), длинный SNI
`aaaa…bbbb…test.example`, 2 повтора; TLS 1.2 — отдельно.

Главная находка: при длинном SNI `split_d4` **не помогает L2**, потому что
разрыв в начале имени оставляет суффикс `test.example` целиком во втором
сегменте. Это переобучение на коротком SNI.

Добавлен `split_multi` (несколько границ через весь SNI). Результат:

| DPI | none | split_d4 | split_multi | mss136 | split4+mss136 |
|---|---|---|---|---|---|
| L1 | **P²** | P | P | P | P |
| L2 | B | B | **P** | B | B |
| L4 | B | B | B | B | B |
| L5 | B | B | B | B | B |

² При длинном PQ-hello L1 обходится **без всякого инструмента**: hello не
помещается в один TCP-сегмент. Это ограничение модели L1, а не заслуга
anti-DPI. Оно специально сохранено в отчёте.

TLS 1.2, L4/L5: `none` и `split_d4` — B; allowed — OK.

Повторный прогон round 2: **80/80 клеток совпали** с первым прогоном
(`results/arena-multi-validation.jsonl` vs
`results/arena-multi-validation-rerun.jsonl`).

## 6. Нижние уровни и datapath

| Уровень / гипотеза | Управляемая величина | Эксперимент | Результат | Ограничение |
|---|---|---|---|---|
| TCP/сегментация | разрывы, MSS | L4 + split_d4, offloads on | B, allowed OK | Поток после сборки тот же |
| TCP/reordering | seq | L4, netem `loss 2% duplicate 2% reorder 25%`, 2 повтора | B, allowed OK | Модель L4 собирает поток; сервер тоже |
| Linux datapath | conntrack | `notrack` в клиенте на priority -300 + L2 + split_d4 | B | `ct original packets` не матчится → split не применяется |
| Linux datapath | GSO/TSO/GRO | тот же L4, offloads on/off | B в обоих; TLS OK | Локальный capture ≠ wire; модель в forward |
| IP | фрагментация | — | **UNTESTED** | NFQUEUE/conntrack делает defrag до forward; для проверки нужна инъекция raw-фрагментов и DPI до defrag. Не реализовано. |
| TCP | overlap/desync | — | **UNTESTED / model-conditioned** | Требует расхождения интерпретации overlap у DPI и сервера; без источника/реализации это предположение, а корректный reassembler даёт тот же поток. Не реализовано. |
| IP | TTL/HopLimit | — | **SKIP** | Нет данных о размещении DPI; изменение TTL ломает связность и не является обоснованным рычагом. |

### Benchmark (L4, allowed SNI, 10 × 64 KiB)

| стратегия | mean | p95 | RSS | CPU ticks |
|---|---|---|---|---|
| none | 49.04 ms | 49.50 ms | — | — |
| split_d4 | 49.18 ms | 49.63 ms | 5044 kB | 0 |

Это локальный veth- стенд, не сетевая пропускная способность. Разница ~0.3%
в пределах шума; инструмент обрабатывает только первые пакеты.

## 7. Что доказано, а что нет

**Доказано в модели:**

* L1/L2 (без сборки TCP) обходятся разбиением ClientHello; `split_multi`
  закрывает переобучение на длинном SNI.
* L3 (агрессивная политика на неполный первый сегмент) ломает и split, и MSS;
  цена — false positives на разрешённых соединениях.
* L4/L5 (полная сборка TCP + разбор TLS/SNI) блокируют все проверенные
  стратегии: none, split d1/d4/d8/multi, MSS 96/136, комбинацию.
* Разбиение и MSS не меняют байтовый поток; после reassembly DPI видит ровно
  то, что видит сервер. Дальнейшая смена границ сегментов не даёт нового
  рычага против такой модели.
* NOTRACK и отсутствие conntrack ломают выбор по `ct original packets` —
  datapath-зависимость, а не сетевой обход.

**Не доказано / не проверено:**

* Поведение реального ТСПУ: размещение DPI, асимметрия маршрута, IP/DNS/QUIC-
  блокировки, allowlist, mid-stream throttling.
* IP-фрагментация и TCP-overlap как рычаги — UNTESTED/model-conditioned.
* TLS record fragmentation / padding / ECH как способ изменить сам поток —
  **не реализовано**. ECH скрывает SNI, но управление ECH не входит в
  mutekizu; фрагментация TLS-записей потенциально может обойти
  reassembling DPI, но требует изменения потока и отдельной проверки
  совместимости.
* Реальная производительность и совместимость на рабочей сети.

## 8. Пределы

* **Предел семейства преобразований:** против DPI, который корректно собирает
  TCP и разбирает TLS, любые изменения границ TCP-сегментов и MSS эквивалентны
  тождественному преобразованию потока. Это предел, а не недостаток реализации.
* **Предел реализации:** нет TLS-record fragmentation/padding, нет IP-
  фрагментации, нет TCP-overlap desync; `split_multi` ограничен 64 границами;
  NOTRACK/отсутствие conntrack отключает split.
* **Предел проверки:** нет доступа к реальному ТСПУ; модели L1-L3 намеренно
  упрощены; IP фрагментация и overlap не проверены; асимметрия путей не
  моделировалась.

## 9. Воспроизведение

```bash
cd ~/mutekizu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure

# Полный раунд 1 (matrix + validation + lower + bench)
unshare -rn python3 tests/arena/arena.py --out tests/arena/results/arena.jsonl

# Раунд 2 (multi-split, tuning + validation), повтор для воспроизводимости
unshare -rn python3 tests/arena/arena.py \
  --levels 1,2,4,5 --strategies none,split_d4,split_multi --families ipv4 \
  --skip-lower --skip-bench \
  --out tests/arena/results/arena-multi-validation-rerun.jsonl
```

Откат: стенд живёт только в `unshare`-namespace; после выхода netns и veth
исчезают. На хосте ничего удалять не нужно. Если процесс арены был убит,
проверить `nft list tables` в текущем netns (на хосте таблиц `mutekizu`/
`arena_dpi` быть не должно).

## 10. Файлы

* `tests/arena/ladder.{hpp,cpp}` — модели L1-L5.
* `tests/arena/dpi_ladder.cpp` — NFQUEUE-обвязка модели.
* `tests/arena/ladder_unit.cpp` — unit-корпус модели (split на каждом offsets,
  out-of-order, duplicate, truncated, malformed, overflow).
* `tests/arena/arena.py` — 3-netns стенд, матрикс, JSONL, summary.
* `tests/arena/results/arena.jsonl`, `summary.md`, `env.json` — раунд 1.
* `tests/arena/results/arena-multi-*.jsonl` — раунд 2 и повтор.
* Изменения утилиты: `split_stride`/`split_max` в `src/config.*`,
  `src/strategy.*`, `src/netpacket.*`, `src/nfq_engine.*`.
