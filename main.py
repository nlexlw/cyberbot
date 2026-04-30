import asyncio
import logging
import os
import re
import secrets
import string
from dataclasses import dataclass
from urllib.parse import urlparse

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton


# Configure logging for easier debugging and observability.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Stores one quiz question with options and the index of the correct option.
@dataclass
class QuizQuestion:
    question: str
    options: list[str]
    correct_index: int


# Suspicious domains list used for basic phishing checks.
SUSPICIOUS_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "secure-login-verify.com",
    "paypal-security-check.com",
    "micr0s0ft-support.com",
}


# Brand-like strings used to detect character substitution tricks.
KNOWN_BRANDS = ["google", "microsoft", "telegram", "paypal", "apple", "bank"]


# Static knowledge cards for quick cyber-hygiene tips.
KNOWLEDGE_CARDS = {
    "Социнженерия": (
        "Не сообщайте коды из SMS и одноразовые пароли. "
        "Проверяйте личность собеседника через официальный канал."
    ),
    "Финансовые данные": (
        "Включите 2FA, используйте отдельную карту для онлайн-покупок "
        "и проверяйте HTTPS и домен сайта."
    ),
    "ИИ и мошенники": (
        "Мошенники используют дипфейки и фишинговые письма с ИИ-текстом. "
        "Проверяйте необычные просьбы через второй канал связи."
    ),
}


# Quiz pool about cyber hygiene and liability in Belarus.
QUIZ_QUESTIONS = [
    QuizQuestion(
        "Что из перечисленного — признак фишинга?",
        [
            "Официальный домен банка",
            "Срочное требование ввести пароль по ссылке",
            "Наличие 2FA",
        ],
        1,
    ),
    QuizQuestion(
        "Какой пароль безопаснее?",
        ["qwerty123", "P@ssword", "V7!kQ2#nL9@z"],
        2,
    ),
    QuizQuestion(
        "Что делать при подозрительном звонке "
        "от якобы сотрудника банка?",
        ["Сообщить CVV", "Перезвонить по номеру с карты", "Установить ПО по ссылке"],
        1,
    ),
    QuizQuestion(
        "Какая мера снижает риск взлома аккаунта?",
        ["Один пароль везде", "Двухфакторная аутентификация", "Отключить обновления"],
        1,
    ),
    QuizQuestion(
        "Что важно помнить о киберпреступлениях в Беларуси?",
        [
            "За вредоносные действия в сети предусмотрена ответственность",
            "В интернете законы не действуют",
            "Ответственность только для компаний",
        ],
        0,
    ),
]


# Stores per-user quiz progress and scores in memory.
user_quiz_state: dict[int, dict[str, int]] = {}


# Builds the main bot menu keyboard.
def build_main_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔎 Проверка ссылки")],
            [KeyboardButton(text="🔐 Сгенерировать пароль")],
            [KeyboardButton(text="🧠 Квиз")],
            [KeyboardButton(text="📚 База знаний")],
        ],
        resize_keyboard=True,
    )


# Creates a keyboard for selecting a knowledge card.
def build_knowledge_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Социнженерия")],
            [KeyboardButton(text="Финансовые данные")],
            [KeyboardButton(text="ИИ и мошенники")],
            [KeyboardButton(text="⬅️ В меню")],
        ],
        resize_keyboard=True,
    )


# Validates a URL and extracts a normalized domain.
def extract_domain(url: str) -> str | None:
    if not re.match(r"^https?://", url.strip(), flags=re.IGNORECASE):
        return None
    parsed = urlparse(url.strip())
    return parsed.netloc.lower().replace("www.", "") if parsed.netloc else None


# Detects brand lookalike substitutions commonly used in phishing links.
def has_brand_substitution(domain: str) -> bool:
    substitutions = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
    normalized = domain.translate(substitutions)
    return any(brand in normalized and brand not in domain for brand in KNOWN_BRANDS)


# Performs a simple phishing risk analysis and returns a human-readable result.
def analyze_link(url: str) -> str:
    domain = extract_domain(url)
    if not domain:
        return "❌ Невалидная ссылка. Пришлите URL в формате https://example.com"

    warnings = []
    if domain in SUSPICIOUS_DOMAINS:
        warnings.append("домен найден в списке подозрительных")
    if has_brand_substitution(domain):
        warnings.append("обнаружена возможная подмена символов бренда")
    if "-" in domain:
        warnings.append("в домене есть дефисы (частый фишинг-признак)")

    if warnings:
        return "⚠️ Потенциально опасная ссылка: " + "; ".join(warnings)
    return "✅ Явных признаков фишинга не найдено, но всегда проверяйте источник."


# Generates a strong random password from letters, digits, and punctuation.
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


# Handles /start and sends greeting with hashtag and menu.
async def cmd_start(message: Message) -> None:
    await message.answer(
        "Привет! Я бот конкурса #КиберПраво. "
        "Помогу проверить ссылки, создать надежный пароль и пройти квиз.",
        reply_markup=build_main_menu(),
    )


# Handles menu navigation and simple commands from text buttons.
async def menu_router(message: Message) -> None:
    text = (message.text or "").strip()
    user_id = message.from_user.id if message.from_user else 0

    if text == "🔐 Сгенерировать пароль":
        await message.answer(f"Ваш безопасный пароль:\n`{generate_password()}`", parse_mode="Markdown")
        return

    if text == "🔎 Проверка ссылки":
        await message.answer("Отправьте ссылку в формате https://example.com")
        return

    if text == "📚 База знаний":
        await message.answer("Выберите тему:", reply_markup=build_knowledge_menu())
        return

    if text in KNOWLEDGE_CARDS:
        await message.answer(f"📌 {text}\n\n{KNOWLEDGE_CARDS[text]}")
        return

    if text == "⬅️ В меню":
        await message.answer("Главное меню:", reply_markup=build_main_menu())
        return

    if text == "🧠 Квиз":
        user_quiz_state[user_id] = {"index": 0, "score": 0}
        await send_quiz_question(message, user_id)
        return

    if user_id in user_quiz_state:
        await handle_quiz_answer(message, user_id)
        return

    if text.startswith("http://") or text.startswith("https://"):
        await message.answer(analyze_link(text))
        return

    await message.answer("Не понял запрос. Выберите действие в меню.")


# Sends the current quiz question to the user.
async def send_quiz_question(message: Message, user_id: int) -> None:
    state = user_quiz_state[user_id]
    idx = state["index"]
    if idx >= len(QUIZ_QUESTIONS):
        score = state["score"]
        await message.answer(
            f"Квиз завершен! Ваш результат: {score}/{len(QUIZ_QUESTIONS)}.",
            reply_markup=build_main_menu(),
        )
        user_quiz_state.pop(user_id, None)
        return

    q = QUIZ_QUESTIONS[idx]
    options = "\n".join(f"{i + 1}. {opt}" for i, opt in enumerate(q.options))
    await message.answer(f"Вопрос {idx + 1}: {q.question}\n\n{options}\n\nОтветьте цифрой 1-3.")


# Processes the user's quiz answer and advances quiz state.
async def handle_quiz_answer(message: Message, user_id: int) -> None:
    text = (message.text or "").strip()
    if text not in {"1", "2", "3"}:
        await message.answer("Пожалуйста, ответьте цифрой: 1, 2 или 3.")
        return

    state = user_quiz_state[user_id]
    question = QUIZ_QUESTIONS[state["index"]]
    if int(text) - 1 == question.correct_index:
        state["score"] += 1
        await message.answer("✅ Верно!")
    else:
        await message.answer("❌ Неверно.")

    state["index"] += 1
    await send_quiz_question(message, user_id)


# Entry point: creates bot, registers handlers, and starts polling.
async def main() -> None:
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("Environment variable BOT_TOKEN is required")

    bot = Bot(token=token)
    dp = Dispatcher()

    dp.message.register(cmd_start, CommandStart())
    dp.message.register(cmd_start, Command("help"))
    dp.message.register(menu_router, F.text)

    await dp.start_polling(bot)


# Runs async main in the standard Python entrypoint.
if __name__ == "__main__":
    asyncio.run(main())
