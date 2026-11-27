import hashlib
import hmac
import json
import logging
import os
import re
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html import escape
from threading import Condition, Lock, local
from zoneinfo import ZoneInfo

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from flask import Flask, jsonify, request

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
USEDESK_TICKET_URL_TEMPLATE = os.getenv("USEDESK_TICKET_URL_TEMPLATE", "")
DIGEST_TIMEZONE = os.getenv("DIGEST_TIMEZONE", "Europe/Moscow")
DIGEST_HOUR = int(os.getenv("DIGEST_HOUR", "18"))
DIGEST_MINUTE = int(os.getenv("DIGEST_MINUTE", "0"))
USEDESK_API_TOKEN = os.getenv("USEDESK_API_TOKEN", "")
USEDESK_API_BASE = os.getenv("USEDESK_API_BASE", "https://secure.usedesk.ru/uapi")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", WEBHOOK_SECRET)
ADMIN_USERS = json.loads(os.getenv("ADMIN_USERS", "[]"))
ADMIN_BY_ID = {int(u["telegram_id"]): u for u in ADMIN_USERS}
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
MAX_LOGIN_ATTEMPTS = 5

STATUS_NAMES = {1: "Открыт", 2: "Выполнен", 3: "Закрыт", 4: "Удалён", 5: "На удержании", 7: "Спам"}
ACTIVE_TICKET_STATUSES = "1,5,6,8"
TICKET_ACTION_STATUSES = {"pause": 5, "resolve": 2}
TICKET_STATUS_HEADINGS = {
    1: "🟢 <b>Заявка открыта</b>",
    2: "✅ <b>Заявка решена</b>",
    3: "✅ <b>Заявка закрыта</b>",
    5: "⏸ <b>Заявка на паузе</b>",
}
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
AGENTS_CACHE_TTL = 300
PROCESSED_IDS_LIMIT = 2000
TICKET_CACHE_LIMIT = 2000
_TAG_RE = re.compile(r"<[^>]+>")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("usedesk-telegram-bot")

app = Flask(__name__)

_ticket_cache: OrderedDict = OrderedDict()
_ticket_cache_changed = Condition()
_http = local()
_daily_count = {"date": None, "count": 0}
_agents_cache = {"agents": [], "fetched_at": None}
_sent_notifications: dict = {}
_processed_comment_ids: set = set()
_notified_tickets: set = set()
_auth_state: dict = {}
_private_updates = OrderedDict()
_private_updates_lock = Lock()
_stats_executor = ThreadPoolExecutor(max_workers=2)
_stats_in_progress = set()


def is_duplicate_private_update(update_id) -> bool:
    if not isinstance(update_id, int):
        return False
    with _private_updates_lock:
        if update_id in _private_updates:
            return True
        _private_updates[update_id] = None
        if len(_private_updates) > PROCESSED_IDS_LIMIT:
            _private_updates.popitem(last=False)
        return False


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
    except (AttributeError, ValueError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return hmac.compare_digest(dk.hex(), hash_hex)


def verify_admin_password(password: str, user: dict) -> bool:
    stored_hash = user.get("password_hash")
    if stored_hash:
        return verify_password(password, stored_hash)
    configured_password = user.get("password", ADMIN_PASSWORD)
    return (
        isinstance(configured_password, str)
        and bool(configured_password.strip())
        and hmac.compare_digest(password.encode(), configured_password.encode())
    )


def http_session() -> requests.Session:
    if not hasattr(_http, "session"):
        _http.session = requests.Session()
    return _http.session


def tg_call(method: str, payload: dict) -> dict | None:
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/{method}"
    try:
        response = http_session().post(url, json=payload, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        status = exc.response.status_code if exc.response is not None else None
        logger.error("Ошибка Telegram API (%s): %s, HTTP %s", method, type(exc).__name__, status)
        return None


def answer_callback_query(callback_id: str, text: str = "", show_alert: bool = False) -> None:
    tg_call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text, "show_alert": show_alert})


def strip_html(text: str) -> str:
    if not text:
        return ""
    text = _TAG_RE.sub("", text).replace("&nbsp;", " ")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)


def register_new_ticket_for_digest() -> None:
    today = datetime.now(ZoneInfo(DIGEST_TIMEZONE)).date().isoformat()
    if _daily_count["date"] != today:
        _daily_count["date"] = today
        _daily_count["count"] = 0
    _daily_count["count"] += 1


def count_tickets_today() -> int:
    with _ticket_cache_changed:
        today = datetime.now(ZoneInfo(DIGEST_TIMEZONE)).date().isoformat()
        return _daily_count["count"] if _daily_count["date"] == today else 0


def usedesk_api_call(endpoint: str, body: dict):
    if not USEDESK_API_TOKEN:
        logger.warning("USEDESK_API_TOKEN не задан")
        return None
    try:
        response = http_session().post(
            f"{USEDESK_API_BASE}/{endpoint}", json={"api_token": USEDESK_API_TOKEN, **body}, timeout=15
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        logger.exception("Ошибка вызова UseDesk API (%s): %s", endpoint, exc)
        return None
    except ValueError:
        logger.error("UseDesk вернул не-JSON ответ на %s", endpoint)
        return None


def fetch_last_client_message(ticket_id) -> str | None:
    """
    Пытается получить текст последнего сообщения клиента через API UseDesk.
    ВАЖНО: точная схема ответа этого метода не подтверждена документацией —
    пробуем несколько вероятных названий полей. Если формат окажется другим,
    будет видно в логах, и мы поправим под реальный ответ.
    """
    data = usedesk_api_call("ticket", {"ticket_id": str(ticket_id)})
    if not isinstance(data, dict):
        logger.warning("Не удалось получить детали заявки %s через API (ответ: %s)", ticket_id, str(data)[:300])
        return None

    comments = data.get("comments") or data.get("messages") or data.get("ticket", {}).get("comments") or []
    if not isinstance(comments, list):
        logger.warning("Неожиданный формат комментариев заявки %s: %s", ticket_id, str(comments)[:300])
        return None

    for comment in reversed(comments):
        if isinstance(comment, dict) and comment.get("client_id") and not comment.get("user_id"):
            text = comment.get("message") or comment.get("text") or ""
            return strip_html(text)

    logger.warning("Не нашли сообщение от клиента среди комментариев заявки %s", ticket_id)
    return None


def get_agents(force_refresh: bool = False) -> list:
    now = time.monotonic()
    fetched_at = _agents_cache["fetched_at"]
    if not force_refresh and fetched_at is not None and now - fetched_at < AGENTS_CACHE_TTL:
        return _agents_cache["agents"]
    data = usedesk_api_call("users", {})
    if not isinstance(data, list):
        return _agents_cache["agents"]
    agents = [{"id": str(a["id"]), "name": a.get("name") or f"Агент {a['id']}"} for a in data]
    _agents_cache.update(agents=agents, fetched_at=time.monotonic())
    return agents


def get_ticket_count(filters: dict) -> int:
    total = 0
    offset = 0
    while True:
        data = usedesk_api_call("tickets", {**filters, "offset": offset})
        if not isinstance(data, list):
            break
        total += len(data)
        if len(data) < 100:
            break
        offset += 1
    return total


def get_active_ticket_count(agent_usedesk_id=None) -> int:
    filters = {"fstatus": ACTIVE_TICKET_STATUSES}
    if agent_usedesk_id:
        filters["fassigned"] = [{"assignee_id": int(agent_usedesk_id)}]
    return get_ticket_count(filters)


def format_my_tickets(user: dict) -> str:
    agent_id = user.get("usedesk_agent_id")
    if not agent_id:
        return "Укажи usedesk_agent_id в ADMIN_USERS. Узнать свой ID в UseDesk можно командой /agents."
    tickets = usedesk_api_call("tickets", {
        "fstatus": ACTIVE_TICKET_STATUSES,
        "fassigned": [{"assignee_id": int(agent_id)}],
        "offset": 0,
    })
    if not isinstance(tickets, list):
        return "Не удалось загрузить заявки из UseDesk."
    if not tickets:
        return "У тебя нет активных заявок."

    lines = ["📋 <b>Мои заявки</b>"]
    for ticket in tickets[:20]:
        ticket_id = escape(str(ticket["id"]))
        subject = escape((ticket.get("subject") or "Без темы")[:100])
        url = build_ticket_url(ticket["id"]) or f"https://secure.usedesk.ru/tickets/{ticket_id}"
        lines.append(f'<a href="{escape(url)}">№ {ticket_id}</a> · {subject}')
    if len(tickets) > 20:
        lines.append("Показаны первые 20 заявок.")
    return "\n".join(lines)


def format_stats_message(user: dict) -> str:
    lines = ["📊 <b>Статистика заявок</b>", ""]
    agent_id = user.get("usedesk_agent_id")
    if agent_id:
        my_count = get_active_ticket_count(agent_id)
        lines.append(f"👤 Назначено на вас: <b>{my_count}</b>")
    else:
        lines.append("👤 Назначено на вас: <i>не настроено (нет usedesk_agent_id)</i>")
    total_count = get_active_ticket_count()
    lines.append(f"🗂 Всего открытых заявок: <b>{total_count}</b>")
    return "\n".join(lines)


def update_ticket(ticket_id, **fields) -> bool:
    data = usedesk_api_call("update/ticket", {"ticket_id": str(ticket_id), **fields})
    return isinstance(data, dict) and data.get("status") == "success"


def assign_ticket(ticket_id, agent_id) -> bool:
    return update_ticket(ticket_id, assignee_id=str(agent_id))


def extract_ticket_info(payload: dict) -> dict:
    ticket = payload.get("ticket", {})
    client = payload.get("client", {})
    emails = client.get("emails") or []
    client_email = emails[0].get("email") if emails else None
    status_id = ticket.get("status_id")

    info = {
        "id": ticket.get("id") or payload.get("ticket_id") or "—",
        "subject": ticket.get("subject") or "Без темы",
        "client_name": client.get("name") or "Неизвестный клиент",
        "client_email": ticket.get("email") or client_email or "—",
        "message": strip_html(ticket.get("message") or ""),
        "status": STATUS_NAMES.get(status_id, f"статус {status_id}" if status_id else "новая"),
    }

    if info["id"] != "—":
        ticket_key = str(info["id"])
        with _ticket_cache_changed:
            _ticket_cache[ticket_key] = {
                "subject": info["subject"],
                "client_name": info["client_name"],
                "client_email": info["client_email"],
            }
            _ticket_cache.move_to_end(ticket_key)
            if len(_ticket_cache) > TICKET_CACHE_LIMIT:
                _ticket_cache.popitem(last=False)
            register_new_ticket_for_digest()
            _ticket_cache_changed.notify_all()

    return info


def is_client_comment(comment: dict) -> bool:
    return bool(comment.get("client_id")) and not comment.get("user_id")


def wait_for_cached_ticket(ticket_id, timeout: float = 3.0) -> dict:
    if not ticket_id:
        return {}
    ticket_key = str(ticket_id)
    with _ticket_cache_changed:
        if not _ticket_cache_changed.wait_for(lambda: ticket_key in _ticket_cache, timeout):
            return {}
        _ticket_cache.move_to_end(ticket_key)
        return _ticket_cache[ticket_key]


def extract_comment_info(payload: dict) -> dict:
    comment = payload.get("comment", {})
    ticket_id = comment.get("ticket_id")
    try:
        ticket_id = int(ticket_id)
    except (TypeError, ValueError):
        pass

    inline_client = payload.get("client") or {}
    inline_emails = inline_client.get("emails") or []
    inline_name = inline_client.get("name")
    inline_email = inline_emails[0].get("email") if inline_emails else None

    cached = wait_for_cached_ticket(ticket_id)

    return {
        "id": ticket_id or "—",
        "subject": cached.get("subject", "—"),
        "client_name": inline_name or cached.get("client_name", "Клиент"),
        "client_email": inline_email or cached.get("client_email", "—"),
        "message": strip_html(comment.get("message") or ""),
        "files": comment.get("files") or [],
    }


def build_header_lines(info: dict) -> list:
    return [
        "🆕 <b>Новая заявка UseDesk</b>",
        f"№ {escape(str(info['id']))}",
        "",
        f"👤 <b>Клиент:</b> {escape(info['client_name'])}",
        f"✉️ <b>Email:</b> {escape(info['client_email'])}",
        f"📝 <b>Тема:</b> {escape(info['subject'])}",
    ]


def format_comment_message(info: dict) -> str:
    message = info["message"].strip()
    if len(message) > 1000:
        message = message[:1000].rstrip() + "…"
    lines = build_header_lines(info) + ["", message or "(пустое сообщение)"]
    return "\n".join(lines)


def build_caption(info: dict) -> str:
    header_text = "\n".join(build_header_lines(info) + [""])
    message = info["message"].strip()
    max_len = max(0, 1024 - len(header_text) - 128)
    if len(message) > max_len:
        message = message[:max_len].rstrip() + "…"
    return header_text + (message or "(пустое сообщение)")


def register_sent_notification(ticket_id, chat_id, message_id, kind: str, base_text: str, *, has_keyboard=True) -> None:
    if not ticket_id or ticket_id == "—" or not message_id:
        return
    _sent_notifications[str(ticket_id)] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "kind": kind,
        "base_text": base_text,
        "assignee_id": None,
        "has_keyboard": has_keyboard,
    }


def sync_ticket_assignee(ticket_id, assignee_id) -> None:
    sent = _sent_notifications.get(str(ticket_id))
    if not sent:
        return
    assignee_key = str(assignee_id) if assignee_id else None
    if assignee_key == sent.get("assignee_id"):
        return
    sent["assignee_id"] = assignee_key
    if not assignee_key:
        return
    agents = get_agents()
    agent_name = next((a["name"] for a in agents if a["id"] == assignee_key), f"Агент {assignee_key}")
    update_notification_with_agent(ticket_id, agent_name)


def insert_agent_line(base_text: str, agent_name: str) -> str:
    agent_line = f"🧑‍💼 <b>Агент:</b> {escape(agent_name[:80])}"
    lines = base_text.split("\n")
    insert_at = len(lines)
    for i, line in enumerate(lines):
        if line.startswith("🧑‍💼 <b>Агент:</b>"):
            lines[i] = agent_line
            return "\n".join(lines)
        if line.startswith("📝 <b>Тема:</b>"):
            insert_at = i + 1
    lines.insert(insert_at, agent_line)
    return "\n".join(lines)


def edit_sent_notification(ticket_id, new_text: str) -> bool:
    sent = _sent_notifications.get(str(ticket_id))
    if not sent:
        logger.warning("Не найдено исходное сообщение для заявки %s", ticket_id)
        return False
    method = "editMessageText" if sent["kind"] == "text" else "editMessageCaption"
    field = "text" if sent["kind"] == "text" else "caption"
    payload = {"chat_id": sent["chat_id"], "message_id": sent["message_id"], field: new_text, "parse_mode": "HTML"}
    if sent["has_keyboard"]:
        keyboard = build_action_keyboard(ticket_id)
        if keyboard:
            payload["reply_markup"] = keyboard
    result = tg_call(method, payload)
    if not result or not result.get("ok"):
        logger.error("Не удалось отредактировать сообщение о заявке %s: %s", ticket_id, result)
        return False
    sent["base_text"] = new_text
    return True


def update_notification_with_agent(ticket_id, agent_name: str) -> None:
    sent = _sent_notifications.get(str(ticket_id))
    if not sent:
        logger.warning("Не найдено исходное сообщение для заявки %s", ticket_id)
        return
    edit_sent_notification(ticket_id, insert_agent_line(sent["base_text"], agent_name))


def sync_ticket_status(ticket_id, status_id) -> None:
    sent = _sent_notifications.get(str(ticket_id))
    heading = TICKET_STATUS_HEADINGS.get(int(status_id)) if str(status_id).isdigit() else None
    if not sent or heading is None:
        return
    current_heading, _, body = sent["base_text"].partition("\n")
    if heading != current_heading:
        edit_sent_notification(ticket_id, f"{heading}\n{body}")


def build_ticket_url(ticket_id) -> str | None:
    if not USEDESK_TICKET_URL_TEMPLATE or not ticket_id or ticket_id == "—":
        return None
    return USEDESK_TICKET_URL_TEMPLATE.replace("{id}", str(ticket_id))


def build_action_keyboard(ticket_id) -> dict | None:
    if not ticket_id or ticket_id == "—":
        return None
    rows = []
    ticket_url = build_ticket_url(ticket_id)
    if ticket_url:
        rows.append([{"text": "🔗 Открыть заявку", "url": ticket_url}])
    if USEDESK_API_TOKEN:
        rows.append([{"text": "👤 Назначить", "callback_data": f"assign:{ticket_id}"}])
        rows[-1].append({"text": "🙋 Взять себе", "callback_data": f"take:{ticket_id}"})
        rows.append([
            {"text": "⏸ На паузу", "callback_data": f"pause:{ticket_id}"},
            {"text": "✅ Решить", "callback_data": f"resolve:{ticket_id}"},
        ])
    return {"inline_keyboard": rows} if rows else None


def _first_present(d: dict, keys: tuple) -> str | None:
    for key in keys:
        if d.get(key):
            return d[key]
    return None


def get_file_url(file_entry) -> str | None:
    if isinstance(file_entry, str):
        return file_entry
    if isinstance(file_entry, dict):
        return _first_present(file_entry, ("url", "file_url", "link", "path", "src"))
    return None


def get_file_name(file_entry) -> str:
    if isinstance(file_entry, dict):
        return _first_present(file_entry, ("name", "filename", "file_name", "title")) or "файл"
    return "файл"


def resolve_files(files: list) -> list:
    resolved = []
    for file_entry in files:
        url = get_file_url(file_entry)
        if not url:
            logger.warning("Не удалось определить ссылку на файл: %s", file_entry)
            continue
        resolved.append({
            "url": url,
            "name": get_file_name(file_entry),
            "is_image": url.lower().split("?")[0].endswith(IMAGE_EXTENSIONS),
        })
    return resolved


def _send_and_register(method: str, payload: dict, ticket_id, kind: str, base_text: str) -> bool:
    keyboard = build_action_keyboard(ticket_id)
    if keyboard:
        payload["reply_markup"] = keyboard
    result = tg_call(method, payload)
    if not result or not result.get("ok"):
        return False
    register_sent_notification(ticket_id, TELEGRAM_CHAT_ID, result["result"]["message_id"], kind, base_text)
    return True


def send_to_telegram(text: str, ticket_id=None) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logger.error("TELEGRAM_TOKEN или TELEGRAM_CHAT_ID не заданы")
        return False
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    return _send_and_register("sendMessage", payload, ticket_id, "text", text)


def send_telegram_single_media(file_info: dict, caption: str, ticket_id=None) -> bool:
    method = "sendPhoto" if file_info["is_image"] else "sendDocument"
    field = "photo" if file_info["is_image"] else "document"
    payload = {"chat_id": TELEGRAM_CHAT_ID, field: file_info["url"], "caption": caption, "parse_mode": "HTML"}
    return _send_and_register(method, payload, ticket_id, "caption", caption)


def send_telegram_media_group(files: list, caption: str, ticket_id=None) -> bool:
    media = []
    for i, file_info in enumerate(files):
        item = {"type": "photo" if file_info["is_image"] else "document", "media": file_info["url"]}
        if i == 0:
            item.update(caption=caption, parse_mode="HTML")
        media.append(item)

    result = tg_call("sendMediaGroup", {"chat_id": TELEGRAM_CHAT_ID, "media": media})
    if not result or not result.get("ok"):
        return False

    sent_messages = result.get("result", [])
    if sent_messages:
        register_sent_notification(
            ticket_id, TELEGRAM_CHAT_ID, sent_messages[0].get("message_id"), "caption", caption, has_keyboard=False
        )

    keyboard = build_action_keyboard(ticket_id)
    if keyboard:
        tg_call("sendMessage", {"chat_id": TELEGRAM_CHAT_ID, "text": "👆 заявка выше", "reply_markup": keyboard})

    return True


def is_duplicate_comment(comment_id) -> bool:
    if comment_id is None:
        return False
    if comment_id in _processed_comment_ids:
        return True
    _processed_comment_ids.add(comment_id)
    if len(_processed_comment_ids) > PROCESSED_IDS_LIMIT:
        for _ in range(PROCESSED_IDS_LIMIT // 2):
            _processed_comment_ids.pop()
    return False


def notify_new_client_message(ticket_id, client_payload: dict) -> None:
    cached = wait_for_cached_ticket(ticket_id)
    emails = client_payload.get("emails") or []
    client_email = emails[0].get("email") if emails else None

    message_text = fetch_last_client_message(ticket_id) or "(не удалось получить текст — откройте заявку по кнопке ниже)"

    info = {
        "id": ticket_id,
        "subject": cached.get("subject", "—"),
        "client_name": client_payload.get("name") or cached.get("client_name", "Клиент"),
        "client_email": client_email or cached.get("client_email", "—"),
        "message": message_text,
    }

    if send_to_telegram(format_comment_message(info), ticket_id=ticket_id):
        _notified_tickets.add(ticket_id)


def handle_trigger_event(payload: dict) -> None:
    trigger = payload.get("trigger", {})
    ticket_id = trigger.get("ticket_id")
    changes = trigger.get("data") or []
    targets = {c.get("target") for c in changes if isinstance(c, dict)}

    if "message_from_client" in targets and ticket_id not in _notified_tickets:
        notify_new_client_message(ticket_id, payload.get("client") or {})
        return

    if str(ticket_id) in _sent_notifications:
        for change in changes:
            if not isinstance(change, dict):
                continue
            if change.get("target") == "assignee_id":
                sync_ticket_assignee(ticket_id, change.get("value"))
            elif change.get("target") in ("status", "status_id"):
                sync_ticket_status(ticket_id, change.get("value"))


@app.route("/usedesk-webhook", methods=["POST"])
def usedesk_webhook():
    if WEBHOOK_SECRET and request.args.get("secret") != WEBHOOK_SECRET:
        logger.warning("Отклонён запрос с неверным secret")
        return jsonify({"error": "forbidden"}), 403

    payload = request.get_json(silent=True)
    if not payload:
        logger.warning("Пустое или невалидное тело запроса")
        return jsonify({"error": "invalid payload"}), 400

    if "trigger" in payload:
        handle_trigger_event(payload)
        return jsonify({"status": "trigger_processed"}), 200

    if "comment" not in payload:
        info = extract_ticket_info(payload)
        ticket_data = payload.get("ticket", {})
        if str(info["id"]) in _sent_notifications:
            sync_ticket_assignee(info["id"], ticket_data.get("assignee_id"))
            sync_ticket_status(info["id"], ticket_data.get("status_id"))
        return jsonify({"status": "cached"}), 200

    comment = payload["comment"]

    if is_duplicate_comment(comment.get("id")):
        logger.info("Дубль вебхука (comment.id=%s) — пропускаем", comment.get("id"))
        return jsonify({"status": "skipped", "reason": "duplicate"}), 200

    if not is_client_comment(comment):
        logger.info("Комментарий не от клиента — пропускаем")
        return jsonify({"status": "skipped", "reason": "not a client comment"}), 200

    ticket_id = comment.get("ticket_id")
    if ticket_id in _notified_tickets:
        logger.info("Заявка %s уже отправлена в Telegram ранее — пропускаем ответ в переписке", ticket_id)
        return jsonify({"status": "skipped", "reason": "already notified"}), 200

    info = extract_comment_info(payload)
    files = resolve_files(info.get("files") or [])

    if not files:
        ok = send_to_telegram(format_comment_message(info), ticket_id=info.get("id"))
    elif len(files) == 1:
        ok = send_telegram_single_media(files[0], build_caption(info), ticket_id=info.get("id"))
    else:
        ok = send_telegram_media_group(files, build_caption(info), ticket_id=info.get("id"))

    if not ok:
        return jsonify({"status": "error", "detail": "telegram send failed"}), 502

    _notified_tickets.add(ticket_id)
    return jsonify({"status": "ok"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "alive"}), 200


PRIVATE_KEYBOARD = {
    "keyboard": [[{"text": "Личный кабинет"}, {"text": "Меню"}], [{"text": "Мои заявки"}]],
    "resize_keyboard": True,
}


def send_private_stats(telegram_id, user: dict, show_tickets: bool) -> None:
    try:
        body = (
            format_my_tickets(user) if show_tickets
            else f"👤 <b>{escape(user['name'])}</b>\n\n{format_stats_message(user)}"
        )
    except Exception:
        logger.exception("Не удалось загрузить статистику личного кабинета")
        body = "⚠️ Не удалось загрузить данные. Попробуйте позже."
    try:
        if _auth_state.get(telegram_id, {}).get("authenticated"):
            tg_call("sendMessage", {
                "chat_id": telegram_id,
                "text": body,
                "parse_mode": "HTML",
                "reply_markup": PRIVATE_KEYBOARD,
            })
    finally:
        with _private_updates_lock:
            _stats_in_progress.discard((telegram_id, show_tickets))


def handle_private_message(message: dict) -> None:
    chat = message.get("chat", {})
    if chat.get("type") != "private":
        return

    telegram_id = chat.get("id")
    text = message.get("text")
    command = text.strip() if isinstance(text, str) else ""
    user = ADMIN_BY_ID.get(telegram_id)
    if not user:
        tg_call("sendMessage", {"chat_id": telegram_id, "text": "⛔ У вас нет доступа к личному кабинету."})
        return

    state = _auth_state.setdefault(
        telegram_id, {"awaiting_password": False, "authenticated": False, "attempts": 0}
    )

    if command == "/logout":
        state.update(authenticated=False, awaiting_password=False)
        tg_call("sendMessage", {
            "chat_id": telegram_id,
            "text": "Вы вышли из личного кабинета.",
            "reply_markup": {"remove_keyboard": True},
        })
        return

    if not state["authenticated"]:
        if state["awaiting_password"] and command and command not in ("/start", "/login"):
            if message.get("message_id"):
                tg_call("deleteMessage", {"chat_id": telegram_id, "message_id": message["message_id"]})

            if state["attempts"] < MAX_LOGIN_ATTEMPTS:
                if verify_admin_password(text, user):
                    state.update(authenticated=True, awaiting_password=False, attempts=0)
                    tg_call("sendMessage", {
                        "chat_id": telegram_id,
                        "text": f"✅ Вы вошли как {user['name']}.",
                        "reply_markup": PRIVATE_KEYBOARD,
                    })
                    return

                state["attempts"] += 1
                if state["attempts"] < MAX_LOGIN_ATTEMPTS:
                    tg_call("sendMessage", {"chat_id": telegram_id, "text": "❌ Неверный пароль. Попробуйте ещё раз."})
                    return

        if state["attempts"] >= MAX_LOGIN_ATTEMPTS:
            tg_call("sendMessage", {
                "chat_id": telegram_id,
                "text": "⛔ Превышено число попыток входа. Обратитесь к администратору.",
            })
            return

        state["awaiting_password"] = True
        tg_call("sendMessage", {"chat_id": telegram_id, "text": "🔐 Введите пароль для входа в личный кабинет:"})
        return

    if command == "/agents":
        agents = get_agents(force_refresh=True)
        if not agents:
            tg_call("sendMessage", {"chat_id": telegram_id, "text": "Не удалось получить список агентов из UseDesk."})
            return
        lines = ["👥 <b>Агенты UseDesk</b>", "", "Найдите себя и впишите ID в ADMIN_USERS как usedesk_agent_id:", ""]
        lines += [f"<code>{agent['id']}</code> — {escape(agent['name'])}" for agent in agents]
        tg_call("sendMessage", {"chat_id": telegram_id, "text": "\n".join(lines), "parse_mode": "HTML"})
        return

    if command in ("Личный кабинет", "/stats", "Мои заявки", "/mytickets"):
        show_tickets = command in ("Мои заявки", "/mytickets")
        key = (telegram_id, show_tickets)
        with _private_updates_lock:
            if key in _stats_in_progress:
                return
            _stats_in_progress.add(key)
        _stats_executor.submit(send_private_stats, telegram_id, user, show_tickets)
        return

    if command not in ("Меню", "/menu", "/start", "/login"):
        return

    tg_call("sendMessage", {
        "chat_id": telegram_id,
        "text": "Личный кабинет — статистика\nМои заявки — список назначенных заявок\n/agents — список агентов UseDesk\n/logout — выйти",
        "reply_markup": PRIVATE_KEYBOARD,
    })


@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook():
    if TELEGRAM_WEBHOOK_SECRET and request.args.get("secret") != TELEGRAM_WEBHOOK_SECRET:
        logger.warning("Отклонён запрос к telegram-webhook с неверным secret")
        return jsonify({"error": "forbidden"}), 403

    update = request.get_json(silent=True) or {}
    message = update.get("message")
    if message:
        if message.get("chat", {}).get("type") == "private" and is_duplicate_private_update(update.get("update_id")):
            return jsonify({"ok": True}), 200
        try:
            handle_private_message(message)
        except Exception:
            logger.exception("Ошибка при обработке личного сообщения")
            chat_id = message.get("chat", {}).get("id")
            if chat_id:
                tg_call("sendMessage", {"chat_id": chat_id, "text": "⚠️ Произошла ошибка. Попробуйте ещё раз или позже."})
        return jsonify({"ok": True}), 200

    callback = update.get("callback_query")
    if not callback:
        return jsonify({"ok": True}), 200

    callback_id = callback.get("id")
    data = callback.get("data", "")
    chat_id = callback.get("message", {}).get("chat", {}).get("id")
    action = re.fullmatch(r"(assign|take|pause|resolve):([0-9]+)|assign_to:([0-9]+):([0-9]+)", data)
    if not action:
        return jsonify({"ok": True}), 200

    user = ADMIN_BY_ID.get(callback.get("from", {}).get("id"))
    if not TELEGRAM_WEBHOOK_SECRET or not user:
        answer_callback_query(callback_id, "У вас нет доступа к действиям с заявками", show_alert=True)
        return jsonify({"ok": True}), 200

    operation, ticket_id, assigned_ticket_id, agent_id = action.groups()
    if operation == "take":
        agent_id = user.get("usedesk_agent_id")
        if not agent_id:
            answer_callback_query(callback_id, "Укажи usedesk_agent_id в ADMIN_USERS", show_alert=True)
        elif assign_ticket(ticket_id, agent_id):
            answer_callback_query(callback_id, "Заявка назначена на тебя")
            sync_ticket_assignee(ticket_id, agent_id)
        else:
            answer_callback_query(callback_id, "Не удалось назначить заявку", show_alert=True)
        return jsonify({"ok": True}), 200

    if operation in TICKET_ACTION_STATUSES:
        status_id = TICKET_ACTION_STATUSES[operation]
        if update_ticket(ticket_id, status=status_id):
            answer_callback_query(callback_id, "Заявка на паузе" if operation == "pause" else "Заявка решена")
            sync_ticket_status(ticket_id, status_id)
        else:
            answer_callback_query(callback_id, "Не удалось изменить статус заявки", show_alert=True)
        return jsonify({"ok": True}), 200

    if operation == "assign":
        agents = get_agents()
        if not agents:
            answer_callback_query(callback_id, "Не удалось получить список агентов", show_alert=True)
            return jsonify({"ok": True}), 200

        keyboard = {
            "inline_keyboard": [
                [{"text": agent["name"], "callback_data": f"assign_to:{ticket_id}:{agent['id']}"}]
                for agent in agents
            ]
        }
        tg_call("sendMessage", {"chat_id": chat_id, "text": f"Кому назначить заявку № {ticket_id}?", "reply_markup": keyboard})
        answer_callback_query(callback_id)

    else:
        ticket_id = assigned_ticket_id
        agents = get_agents()
        agent_name = next((a["name"] for a in agents if a["id"] == agent_id), agent_id)
        message_id = callback.get("message", {}).get("message_id")

        if assign_ticket(ticket_id, agent_id):
            answer_callback_query(callback_id, f"Назначено: {agent_name}")
            if message_id:
                tg_call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
            update_notification_with_agent(ticket_id, agent_name)
            sent = _sent_notifications.get(str(ticket_id))
            if sent:
                sent["assignee_id"] = str(agent_id)
        else:
            answer_callback_query(callback_id, "Не удалось назначить заявку", show_alert=True)

    return jsonify({"ok": True}), 200


def ensure_telegram_webhook() -> None:
    if not BASE_URL:
        logger.warning("BASE_URL не задан — кнопка «Назначить» работать не будет")
        return
    webhook_url = f"{BASE_URL}/telegram-webhook"
    if TELEGRAM_WEBHOOK_SECRET:
        webhook_url += f"?secret={TELEGRAM_WEBHOOK_SECRET}"
    result = tg_call("setWebhook", {"url": webhook_url})
    if result and result.get("ok"):
        logger.info("Telegram webhook зарегистрирован")
    else:
        logger.error("Не удалось зарегистрировать Telegram webhook: %s", result)


def send_daily_digest() -> None:
    count = count_tickets_today()
    send_to_telegram(f"📊 <b>Сводка за сегодня</b>\n\nЗаявок за день: <b>{count}</b>")
    logger.info("Отправлена ежедневная сводка: %s заявок", count)


ensure_telegram_webhook()

scheduler = BackgroundScheduler(timezone=DIGEST_TIMEZONE)
scheduler.add_job(send_daily_digest, "cron", hour=DIGEST_HOUR, minute=DIGEST_MINUTE)
scheduler.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
