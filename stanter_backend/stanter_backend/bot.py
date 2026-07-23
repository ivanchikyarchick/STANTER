"""Minimal STANTER Telegram bot: /start opens the Mini App."""
import json
import os
import time
import urllib.parse
import urllib.request

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "")
API = f"https://api.telegram.org/bot{TOKEN}"


def call(method, payload=None):
    data = urllib.parse.urlencode(payload or {}).encode()
    with urllib.request.urlopen(f"{API}/{method}", data=data, timeout=30) as response:
        return json.loads(response.read())


def send_start(chat_id):
    keyboard = {"inline_keyboard": [[{"text": "⚡ Відкрити STANTER", "web_app": {"url": PUBLIC_URL}}]]}
    call("sendMessage", {
        "chat_id": chat_id,
        "text": "⚡ STANTER готовий. Записуй станти, відкривай досягнення та змагайся з райдерами!",
        "reply_markup": json.dumps(keyboard),
    })


def main():
    if not TOKEN or not PUBLIC_URL.startswith("https://"):
        raise SystemExit("Set TELEGRAM_BOT_TOKEN and HTTPS PUBLIC_URL")
    call("setChatMenuButton", {"menu_button": json.dumps({
        "type": "web_app", "text": "Відкрити STANTER", "web_app": {"url": PUBLIC_URL}
    })})
    offset = 0
    while True:
        try:
            updates = call("getUpdates", {"offset": offset, "timeout": 25}).get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                message = update.get("message", {})
                if message.get("text", "").startswith("/start"):
                    send_start(message["chat"]["id"])
        except Exception as error:
            print(f"Bot error: {error}", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
