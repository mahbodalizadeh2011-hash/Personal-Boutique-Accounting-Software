# -*- coding: utf-8 -*-
"""
نرم‌افزار حسابداری مزون - نسخه PyQt6 v8.5.3
بر پایه ساختار نرم‌افزار حسابداری قبلی، با:
- ورود دوگانه مزون / شخصی
- دیتابیس جداگانه برای هر حساب
- رابط PyQt6
- نمایش نشانی ثابت IP Address = 192.168.1.4
- مشتری، تاریخ تولد و آماده‌سازی پیامک
- درآمد، هزینه، طرف حساب، فاکتور، گزارش، پشتیبان‌گیری و تنظیمات

نکته:
ارسال واقعی SMS به API یک پنل پیامکی در مرحله اتصال سرویس انجام می‌شود.
"""

import csv
import os
import shutil
import sqlite3
import sys
import threading
import secrets
import html
import json
import hashlib
import hmac
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, urlencode
from urllib.request import Request, urlopen
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QDate, QCalendar, QLocale
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog, QMessageBox, QFileDialog,
    QLabel, QPushButton, QLineEdit, QComboBox, QDateEdit, QCalendarWidget, QDoubleSpinBox,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QHBoxLayout, QGridLayout, QFormLayout, QGroupBox, QFrame, QStackedWidget,
    QTextEdit, QHeaderView, QAbstractItemView, QCheckBox
)

APP_TITLE = "حسابداری مزون"
APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Hesabdari"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

LEGACY_DB = Path.cwd() / "hesabdari.db"
MAISON_DB = APP_DATA_DIR / "hesabdari_maison.db"
PERSONAL_DB = APP_DATA_DIR / "hesabdari_personal.db"

DEFAULT_USERS = {
    # حسابداری مزون
    "nami": ("nami1403", "maison"),
    # حسابداری شخصی
    "parastoo": ("parastoo1367", "personal"),
}
AUTH_FILE = APP_DATA_DIR / "auth_users.json"


def _password_record(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 240000).hex()
    return {"salt": salt, "hash": digest}


def load_users():
    """Load persistent credentials, migrating the original defaults on first run."""
    try:
        raw = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and raw:
            users = {}
            for username, rec in raw.items():
                if isinstance(rec, dict) and rec.get("role") in ("maison", "personal") and rec.get("salt") and rec.get("hash"):
                    users[username] = rec
            if users:
                return users
    except (OSError, ValueError, TypeError):
        pass
    users = {}
    for username, (password, role) in DEFAULT_USERS.items():
        users[username] = {**_password_record(password), "role": role}
    save_users(users)
    return users


def save_users(users):
    temp = AUTH_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, AUTH_FILE)


def authenticate(username, password):
    rec = load_users().get(username)
    if not rec:
        return None
    candidate = _password_record(password, rec["salt"])["hash"]
    return rec["role"] if hmac.compare_digest(candidate, rec["hash"]) else None


def username_for_role(role):
    for username, rec in load_users().items():
        if rec["role"] == role:
            return username
    return ""


def change_credentials(role, current_password, new_username, new_password):
    users = load_users()
    current_username = username_for_role(role)
    if not current_username or authenticate(current_username, current_password) != role:
        return False, "رمز عبور فعلی صحیح نیست."
    new_username = new_username.strip()
    if len(new_username) < 3 or any(ch.isspace() for ch in new_username):
        return False, "نام کاربری باید حداقل ۳ نویسه و بدون فاصله باشد."
    if len(new_password) < 6:
        return False, "رمز عبور جدید باید حداقل ۶ نویسه باشد."
    if new_username != current_username and new_username in users:
        return False, "این نام کاربری قبلاً برای یکی از حساب‌ها ثبت شده است."
    rec = users.pop(current_username)
    rec.update(_password_record(new_password), role=role)
    users[new_username] = rec
    save_users(users)
    return True, "نام کاربری و رمز عبور با موفقیت تغییر کرد. برای ورود بعدی از اطلاعات جدید استفاده کنید."

WEB_HOST = "0.0.0.0"  # روی همه رابط‌های شبکه گوش بده؛ این مقدار را به IP محلی تغییر نده
WEB_PORT = 8000
PREFERRED_LOCAL_IP = "192.168.1.4"  # IP محلی ترجیحی برای نمایش لینک؛ باید متعلق به همین کامپیوتر باشد
WEB_BIND_NOTE = "0.0.0.0"  # دسترسی از LAN و Tailscale


def resource_path(name):
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / name


def fa_digits(value):
    return str(value).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))


def en_digits(value):
    return str(value).translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789"))


def money(value):
    try:
        return fa_digits(f"{Decimal(str(value)):,.0f}")
    except Exception:
        return "۰"


def parse_amount(value):
    value = en_digits(value).replace(",", "").replace("٬", "").replace(" ", "").strip()
    if not value:
        raise InvalidOperation
    n = Decimal(value)
    if n < 0:
        raise InvalidOperation
    return int(n)


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today():
    return date.today().isoformat()


def setup_jalali_date_edit(widget):
    """
    تاریخ‌نگار جلالی کامل برای QDateEdit.

    ظاهر و انتخاب تاریخ با تقویم شمسی است، اما مقدار داخلی همچنان QDate
    و در نتیجه میلادی/ISO باقی می‌ماند تا دیتابیس و گزارش‌های قبلی خراب نشوند.
    """
    jalali = QCalendar(QCalendar.System.Jalali)
    widget.setCalendar(jalali)
    widget.setCalendarPopup(True)
    widget.setDisplayFormat("yyyy/MM/dd")
    widget.setDate(QDate.currentDate())
    widget.setLocale(QLocale("fa_IR"))

    # تقویم بازشونده را هم صریحاً جلالی و فارسی می‌کنیم.
    calendar_widget = QCalendarWidget()
    calendar_widget.setCalendar(jalali)
    calendar_widget.setLocale(QLocale("fa_IR"))
    calendar_widget.setFirstDayOfWeek(Qt.DayOfWeek.Saturday)
    calendar_widget.setHorizontalHeaderFormat(
        QCalendarWidget.HorizontalHeaderFormat.LongDayNames
    )
    calendar_widget.setVerticalHeaderFormat(
        QCalendarWidget.VerticalHeaderFormat.NoVerticalHeader
    )
    calendar_widget.setGridVisible(True)
    calendar_widget.setDateEditEnabled(True)
    calendar_widget.setNavigationBarVisible(True)
    calendar_widget.setSelectedDate(QDate.currentDate())
    widget.setCalendarWidget(calendar_widget)

    return widget


def jalali_display_from_iso(iso_date):
    """نمایش تاریخ ذخیره‌شده میلادی به شکل شمسی برای جدول‌ها."""
    try:
        qd = QDate.fromString(str(iso_date)[:10], "yyyy-MM-dd")
        if qd.isValid():
            cal = QCalendar(QCalendar.System.Jalali)
            parts = cal.partsFromDate(qd)
            return f"{parts.year:04d}/{parts.month:02d}/{parts.day:02d}"
    except Exception:
        pass
    return str(iso_date)


def jalali_parts_from_iso(iso_date):
    try:
        qd = QDate.fromString(str(iso_date)[:10], "yyyy-MM-dd")
        if not qd.isValid():
            return None
        return QCalendar(QCalendar.System.Jalali).partsFromDate(qd)
    except Exception:
        return None


def iso_from_jalali(value):
    """تبدیل ۱۴۰۵/۰۷/۰۹ یا 1405-07-09 به تاریخ ISO میلادی."""
    raw = en_digits(str(value)).strip().replace("-", "/").replace(".", "/")
    parts = [x for x in raw.split("/") if x]
    if len(parts) != 3:
        raise ValueError("تاریخ شمسی باید به شکل 1405/07/09 باشد")
    y, m, d = map(int, parts)
    qd = QCalendar(QCalendar.System.Jalali).dateFromParts(y, m, d)
    if not qd.isValid():
        raise ValueError("تاریخ شمسی معتبر نیست")
    return qd.toString("yyyy-MM-dd")


def jalali_today():
    p = QCalendar(QCalendar.System.Jalali).partsFromDate(QDate.currentDate())
    return f"{p.year:04d}/{p.month:02d}/{p.day:02d}"


def jalali_month_day_from_iso(iso_date):
    p = jalali_parts_from_iso(iso_date)
    return (p.month, p.day) if p else None


JALALI_MONTHS = [
    "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
    "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"
]


def copy_legacy_if_needed(target):
    target = Path(target)
    if target.exists():
        return
    if target == MAISON_DB and LEGACY_DB.exists():
        try:
            shutil.copy2(LEGACY_DB, target)
        except Exception:
            pass


class Database:
    def __init__(self, path):
        copy_legacy_if_needed(path)
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_tables()

    def create_tables(self):
        c = self.conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK(id=1),
                business_name TEXT NOT NULL DEFAULT 'مزون من',
                currency TEXT NOT NULL DEFAULT 'تومان',
                instagram TEXT DEFAULT '',
                birthday_discount INTEGER NOT NULL DEFAULT 20,
                sms_enabled INTEGER NOT NULL DEFAULT 0,
                sms_api_url TEXT DEFAULT '',
                sms_api_key TEXT DEFAULT '',
                sms_sender TEXT DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS parties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                national_id TEXT,
                address TEXT,
                notes TEXT,
                birth_date TEXT,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_type TEXT NOT NULL CHECK(tx_type IN ('income','expense')),
                title TEXT NOT NULL,
                amount INTEGER NOT NULL,
                tx_date TEXT NOT NULL,
                party_id INTEGER,
                description TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(party_id) REFERENCES parties(id) ON DELETE SET NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_no TEXT NOT NULL UNIQUE,
                invoice_type TEXT NOT NULL CHECK(invoice_type IN ('sale','purchase')),
                party_id INTEGER,
                invoice_date TEXT NOT NULL,
                discount INTEGER NOT NULL DEFAULT 0,
                paid INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(party_id) REFERENCES parties(id) ON DELETE SET NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS invoice_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                item_name TEXT NOT NULL,
                quantity REAL NOT NULL,
                unit_price INTEGER NOT NULL,
                FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS birthday_sms_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                party_id INTEGER NOT NULL,
                birthday_year INTEGER NOT NULL,
                status TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                UNIQUE(party_id, birthday_year),
                FOREIGN KEY(party_id) REFERENCES parties(id) ON DELETE CASCADE
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                quantity REAL NOT NULL DEFAULT 0,
                unit TEXT NOT NULL DEFAULT 'عدد',
                note TEXT,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS asset_movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('increase','decrease')),
                quantity REAL NOT NULL,
                movement_date TEXT NOT NULL,
                note TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
            )
        """)
        c.execute("INSERT OR IGNORE INTO settings(id) VALUES(1)")
        self._add_column_if_missing("parties", "birth_date", "TEXT")
        self._add_column_if_missing("settings", "instagram", "TEXT DEFAULT ''")
        self._add_column_if_missing("settings", "birthday_discount", "INTEGER DEFAULT 20")
        self._add_column_if_missing("settings", "sms_enabled", "INTEGER DEFAULT 0")
        self._add_column_if_missing("settings", "sms_api_url", "TEXT DEFAULT ''")
        self._add_column_if_missing("settings", "sms_api_key", "TEXT DEFAULT ''")
        self._add_column_if_missing("settings", "sms_sender", "TEXT DEFAULT ''")
        self.conn.commit()

    def _add_column_if_missing(self, table, column, definition):
        cols = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def log(self, action, details=""):
        self.conn.execute(
            "INSERT INTO audit_log(action, details, created_at) VALUES(?,?,?)",
            (action, details, now_text())
        )
        self.conn.commit()

    def close(self):
        self.conn.close()


class LoginDialog(QDialog):
    """Premium login screen with a dedicated background image and real input controls."""
    DESIGN_W = 1536
    DESIGN_H = 1024

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ورود به نرم‌افزار حسابداری")
        self.setFixedSize(1152, 768)
        self.setObjectName("premiumLoginDialog")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        # Dedicated login artwork. Keep it as an application asset so it also works in a PyInstaller build.
        self.background = QLabel(self)
        self.background.setGeometry(0, 0, self.width(), self.height())
        self.background.setPixmap(QIcon().pixmap(1, 1))  # replaced immediately below
        from PyQt6.QtGui import QPixmap
        self._login_pixmap = QPixmap(str(resource_path("login_background.png")))
        if not self._login_pixmap.isNull():
            self.background.setPixmap(self._login_pixmap.scaled(
                self.size(), Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
        self.background.setScaledContents(True)
        self.background.lower()

        # The generated artwork contains visual mock fields; these widgets sit precisely over them
        # so typing and login remain functional rather than being a static screenshot.
        self.username = QLineEdit(self)
        self.username.setPlaceholderText("نام کاربری")
        self.username.setGeometry(704, 296, 326, 52)
        self.username.setStyleSheet("QLineEdit { background: rgba(10, 28, 49, 245); color: white; border: 1px solid #344a64; border-radius: 10px; padding: 8px 14px; font-size: 12pt; }")
        self.username.setAlignment(Qt.AlignmentFlag.AlignRight)

        self.password = QLineEdit(self)
        self.password.setPlaceholderText("رمز عبور")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setGeometry(704, 364, 326, 52)
        self.password.setStyleSheet("QLineEdit { background: rgba(10, 28, 49, 245); color: white; border: 1px solid #344a64; border-radius: 10px; padding: 8px 14px; font-size: 12pt; }")
        self.password.setAlignment(Qt.AlignmentFlag.AlignRight)

        self.error = QLabel("", self)
        self.error.setGeometry(685, 420, 350, 22)
        self.error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error.setStyleSheet("color: #ff9696; background: transparent; font-size: 10pt;")

        self.login_button = QPushButton("ورود", self)
        self.login_button.setGeometry(682, 438, 326, 48)
        self.login_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_button.setStyleSheet("QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #ffdf9a, stop:1 #b6813f); color: #071b30; border: 0; border-radius: 10px; padding: 8px; font-size: 13pt; font-weight: bold; } QPushButton:hover { background: #ffe8b6; } QPushButton:pressed { background: #c99753; }")
        self.login_button.clicked.connect(self.accept_login)
        self.password.returnPressed.connect(self.accept_login)
        self.username.returnPressed.connect(lambda: self.password.setFocus())
        self.username.setFocus()

    def resizeEvent(self, event):
        # Keep the image and controls aligned if the dialog geometry is adjusted later.
        if hasattr(self, "background"):
            self.background.setGeometry(0, 0, self.width(), self.height())
        super().resizeEvent(event)

    def accept_login(self):
        u = self.username.text().strip()
        p = self.password.text()
        role = authenticate(u, p)
        if role:
            self.role = role
            self.accept()
        else:
            self.error.setText("نام کاربری یا رمز عبور اشتباه است.")


class Card(QFrame):
    def __init__(self, title, value="۰"):
        super().__init__()
        self.setObjectName("card")
        l = QVBoxLayout(self)
        t = QLabel(title)
        t.setObjectName("cardTitle")
        self.value = QLabel(value)
        self.value.setObjectName("cardValue")
        l.addWidget(t)
        l.addWidget(self.value)


class AccountingWindow(QMainWindow):
    def __init__(self, role):
        super().__init__()
        self.role = role
        self.db_path = MAISON_DB if role == "maison" else PERSONAL_DB
        self.db = Database(self.db_path)
        self.setWindowTitle("حسابداری مزون" if role == "maison" else "حسابداری شخصی")
        self.resize(1400, 850)
        self.setMinimumSize(1100, 700)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self._build_ui()
        self._load_settings()
        self.refresh_all()
        self.web_server = LocalWebServer(self)
        self.web_server.start()

        if self.role == "maison":
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.check_birthdays)
            self.timer.start(60 * 60 * 1000)
            QTimer.singleShot(1200, self.check_birthdays)

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("mainCentral")
        self.setCentralWidget(central)
        central.setStyleSheet(f'QWidget#mainCentral {{ background-image: url("{resource_path("background_hesabdari.png").as_posix()}"); background-repeat: no-repeat; background-position: center; }}')
        root = QVBoxLayout(central)
        header = QFrame()
        header.setObjectName("header")
        hl = QHBoxLayout(header)
        title = QLabel("حسابداری مزون" if self.role == "maison" else "حسابداری شخصی")
        title.setObjectName("headerTitle")
        self.web_label = QLabel("IP Address = 192.168.1.4")
        self.logout_btn = QPushButton("خروج")
        self.logout_btn.clicked.connect(self.close)
        hl.addWidget(title)
        hl.addStretch()
        hl.addWidget(self.web_label)
        hl.addWidget(self.logout_btn)
        root.addWidget(header)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        self.dashboard_tab = QWidget()
        self.tx_tab = QWidget()
        self.party_tab = QWidget()
        self.invoice_tab = QWidget()
        self.asset_tab = QWidget()
        self.report_tab = QWidget()
        self.settings_tab = QWidget()

        self.tabs.addTab(self.dashboard_tab, "داشبورد")
        self.tabs.addTab(self.tx_tab, "درآمد و هزینه")
        self.tabs.addTab(self.party_tab, "طرف حساب‌ها")
        self.tabs.addTab(self.invoice_tab, "فاکتورها")
        # دارایی‌ها برای هر دو نوع حساب فعال است؛ دیتابیس هر نقش جدا می‌ماند.
        self.tabs.addTab(self.asset_tab, "دارایی‌ها")
        self.tabs.addTab(self.report_tab, "گزارش‌ها")
        self.tabs.addTab(self.settings_tab, "تنظیمات")

        self._build_dashboard()
        self._build_transactions()
        self._build_parties()
        self._build_invoices()
        self._build_assets()
        self._build_reports()
        self._build_settings()

    def _build_dashboard(self):
        l = QVBoxLayout(self.dashboard_tab)
        cards = QHBoxLayout()
        self.income_card = Card("مجموع درآمد")
        self.expense_card = Card("مجموع هزینه")
        self.balance_card = Card("مانده")
        self.party_card = Card("طرف حساب‌ها")
        for c in (self.income_card, self.expense_card, self.balance_card, self.party_card):
            cards.addWidget(c)
        l.addLayout(cards)

        if self.role == "maison":
            birthday_box = QGroupBox("🎂 تولدهای امروز")
            bl = QVBoxLayout(birthday_box)
            self.birthday_table = QTableWidget(0, 4)
            self.birthday_table.setHorizontalHeaderLabels(["نام", "موبایل", "تخفیف", "وضعیت پیام"])
            self.birthday_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            bl.addWidget(self.birthday_table)
            birthday_actions = QHBoxLayout()
            send_selected = QPushButton("ارسال پیامک به مشتری انتخاب‌شده")
            send_selected.clicked.connect(self.send_selected_birthday_sms)
            birthday_actions.addWidget(send_selected)
            birthday_actions.addStretch()
            bl.addLayout(birthday_actions)
            l.addWidget(birthday_box)

        box = QGroupBox("آخرین تراکنش‌ها")
        vl = QVBoxLayout(box)
        self.dashboard_table = QTableWidget(0, 5)
        self.dashboard_table.setHorizontalHeaderLabels(["شناسه", "نوع", "عنوان", "مبلغ", "تاریخ"])
        self.dashboard_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.dashboard_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        vl.addWidget(self.dashboard_table)
        l.addWidget(box)

    def _build_transactions(self):
        l = QVBoxLayout(self.tx_tab)
        form = QGroupBox("ثبت تراکنش")
        grid = QGridLayout(form)
        self.tx_type = QComboBox()
        self.tx_type.addItems(["درآمد", "هزینه"])
        self.tx_title = QLineEdit()
        self.tx_amount = QLineEdit()
        self.tx_date = setup_jalali_date_edit(QDateEdit())
        self.tx_party = QComboBox()
        self.tx_description = QLineEdit()

        fields = [
            ("نوع", self.tx_type), ("عنوان", self.tx_title),
            ("مبلغ", self.tx_amount), ("تاریخ", self.tx_date),
            ("طرف حساب", self.tx_party), ("توضیحات", self.tx_description)
        ]
        for i, (lab, w) in enumerate(fields):
            grid.addWidget(QLabel(lab), i // 3 * 2, (i % 3) * 2)
            grid.addWidget(w, i // 3 * 2, (i % 3) * 2 + 1)
        add = QPushButton("ثبت تراکنش")
        add.clicked.connect(self.add_transaction)
        clear = QPushButton("پاک کردن")
        clear.clicked.connect(self.clear_tx_form)
        grid.addWidget(add, 4, 3)
        grid.addWidget(clear, 4, 5)
        l.addWidget(form)

        search = QHBoxLayout()
        self.tx_search = QLineEdit()
        self.tx_search.setPlaceholderText("جستجو در عنوان، توضیحات یا طرف حساب...")
        self.tx_search.textChanged.connect(self.load_transactions)
        search.addWidget(self.tx_search)
        delete = QPushButton("حذف تراکنش انتخاب‌شده")
        delete.clicked.connect(self.delete_transaction)
        search.addWidget(delete)

        export = QPushButton("خروجی CSV تراکنش‌ها")
        export.clicked.connect(self.export_transactions_csv)
        search.addWidget(export)

        l.addLayout(search)

        self.tx_table = QTableWidget(0, 7)
        self.tx_table.setHorizontalHeaderLabels(
            ["شناسه", "نوع", "عنوان", "مبلغ", "تاریخ", "طرف حساب", "توضیحات"]
        )
        self.tx_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tx_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tx_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        l.addWidget(self.tx_table)

    def _build_parties(self):
        l = QVBoxLayout(self.party_tab)
        form = QGroupBox("ثبت طرف حساب")
        f = QGridLayout(form)
        self.p_name = QLineEdit()
        self.p_phone = QLineEdit()
        self.p_national = QLineEdit()
        self.p_address = QLineEdit()
        self.p_notes = QLineEdit()
        vals = [("نام", self.p_name), ("موبایل", self.p_phone), ("کد ملی", self.p_national), ("آدرس", self.p_address)]
        if self.role == "maison":
            self.p_birth = setup_jalali_date_edit(QDateEdit())
            self.p_birth.setSpecialValueText("بدون تاریخ تولد")
            self.p_birth_optional = QCheckBox("تاریخ تولد ثبت نشده")
            self.p_birth_optional.setChecked(True)
            self.p_birth_optional.toggled.connect(lambda checked: self.p_birth.setEnabled(not checked))
            vals.append(("تاریخ تولد", self.p_birth))
        vals.append(("یادداشت", self.p_notes))
        for i, (lab, w) in enumerate(vals):
            f.addWidget(QLabel(lab), i // 3 * 2, (i % 3) * 2)
            f.addWidget(w, i // 3 * 2, (i % 3) * 2 + 1)
        add = QPushButton("ثبت طرف حساب")
        add.clicked.connect(self.add_party)
        f.addWidget(add, ((len(vals) + 2) // 3) * 2, 5)
        if self.role == "maison":
            f.addWidget(self.p_birth_optional, ((len(vals) + 2) // 3) * 2 - 1, 5)
        l.addWidget(form)
        row = QHBoxLayout()
        delete = QPushButton("حذف انتخاب‌شده")
        delete.clicked.connect(self.delete_party)
        export = QPushButton("خروجی CSV")
        export.clicked.connect(self.export_parties_csv)
        row.addWidget(delete)
        row.addWidget(export)
        row.addStretch()
        l.addLayout(row)
        self.party_table = QTableWidget(0, 7 if self.role == "maison" else 6)
        headers = (["شناسه", "نام", "موبایل", "کد ملی", "آدرس", "تولد", "یادداشت"] if self.role == "maison" else ["شناسه", "نام", "موبایل", "کد ملی", "آدرس", "یادداشت"])
        self.party_table.setHorizontalHeaderLabels(headers)
        self.party_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.party_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        l.addWidget(self.party_table)

    def _build_invoices(self):
        l = QVBoxLayout(self.invoice_tab)
        form = QGroupBox("ثبت فاکتور")
        g = QGridLayout(form)
        self.inv_no = QLineEdit()
        self.inv_type = QComboBox(); self.inv_type.addItems(["فروش", "خرید"])
        self.inv_date = setup_jalali_date_edit(QDateEdit())
        self.inv_party = QComboBox()
        self.inv_discount = QLineEdit("0")
        self.inv_paid = QLineEdit("0")
        self.inv_notes = QLineEdit()
        fields = [("شماره فاکتور", self.inv_no), ("نوع", self.inv_type),
                  ("تاریخ", self.inv_date), ("طرف حساب", self.inv_party),
                  ("تخفیف", self.inv_discount), ("دریافت/پرداخت", self.inv_paid),
                  ("یادداشت", self.inv_notes)]
        for i, (lab, w) in enumerate(fields):
            g.addWidget(QLabel(lab), i // 4 * 2, (i % 4) * 2)
            g.addWidget(w, i // 4 * 2, (i % 4) * 2 + 1)
        l.addWidget(form)

        item_box = QGroupBox("اقلام فاکتور")
        ig = QGridLayout(item_box)
        self.inv_item_name = QLineEdit()
        self.inv_item_qty = QLineEdit("1")
        self.inv_item_price = QLineEdit("0")
        ig.addWidget(QLabel("نام کالا/خدمت"), 0, 0); ig.addWidget(self.inv_item_name, 0, 1)
        ig.addWidget(QLabel("تعداد"), 0, 2); ig.addWidget(self.inv_item_qty, 0, 3)
        ig.addWidget(QLabel("قیمت واحد"), 0, 4); ig.addWidget(self.inv_item_price, 0, 5)
        add_item = QPushButton("افزودن قلم")
        add_item.clicked.connect(self.add_invoice_item)
        ig.addWidget(add_item, 0, 6)
        self.inv_items = QTableWidget(0, 5)
        self.inv_items.setHorizontalHeaderLabels(["نام", "تعداد", "قیمت واحد", "جمع", "حذف"])
        self.inv_items.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.inv_items.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inv_items.cellClicked.connect(lambda row, col: self.remove_invoice_item(row) if col == 4 else None)
        ig.addWidget(self.inv_items, 1, 0, 1, 7)
        l.addWidget(item_box)

        actions = QHBoxLayout()
        add = QPushButton("ثبت فاکتور")
        add.clicked.connect(self.add_invoice)
        delete_inv = QPushButton("حذف فاکتور انتخاب‌شده")
        delete_inv.clicked.connect(self.delete_invoice)
        actions.addWidget(add); actions.addWidget(delete_inv); actions.addStretch()
        l.addLayout(actions)
        self.invoice_table = QTableWidget(0, 8)
        self.invoice_table.setHorizontalHeaderLabels(["شناسه", "شماره", "نوع", "طرف حساب", "تاریخ", "جمع اقلام", "تخفیف", "پرداخت"])
        self.invoice_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.invoice_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        l.addWidget(self.invoice_table)

    def _build_assets(self):
        l = QVBoxLayout(self.asset_tab)
        form = QGroupBox("دارایی")
        g = QGridLayout(form)
        self.asset_name = QLineEdit()
        self.asset_type = QComboBox()
        if self.role == "maison":
            self.asset_type.addItems([
                "تجهیزات فروشگاه پوشاک",
                "تجهیزات کارگاه خیاطی",
                "سایر تجهیزات مزون",
            ])
        else:
            self.asset_type.addItems([
                "نقد", "بانک", "طلا", "دلار", "سکه", "ارز", "ملک",
                "خودرو", "سهام", "کریپتو", "تجهیزات", "سایر"
            ])
        self.asset_qty = QLineEdit("0")
        self.asset_unit = QLineEdit("عدد")
        self.asset_note = QLineEdit()
        for i, (lab, w) in enumerate([
            ("نام دارایی", self.asset_name), ("نوع", self.asset_type),
            ("مقدار", self.asset_qty), ("واحد", self.asset_unit), ("یادداشت", self.asset_note)
        ]):
            g.addWidget(QLabel(lab), i // 3 * 2, (i % 3) * 2)
            g.addWidget(w, i // 3 * 2, (i % 3) * 2 + 1)
        add = QPushButton("ثبت دارایی")
        add.clicked.connect(self.add_asset)
        g.addWidget(add, 2, 5)
        l.addWidget(form)
        asset_actions = QHBoxLayout()
        delete_asset = QPushButton("حذف دارایی انتخاب‌شده")
        delete_asset.clicked.connect(self.delete_asset)
        asset_actions.addWidget(delete_asset)
        asset_actions.addStretch()
        l.addLayout(asset_actions)
        self.asset_table = QTableWidget(0, 6)
        self.asset_table.setHorizontalHeaderLabels(["شناسه", "نام", "نوع", "مقدار", "واحد", "یادداشت"])
        self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        l.addWidget(self.asset_table)

    def _build_reports(self):
        l = QVBoxLayout(self.report_tab)
        row = QHBoxLayout()
        refresh = QPushButton("به‌روزرسانی گزارش")
        refresh.clicked.connect(self.load_reports)
        export = QPushButton("خروجی CSV تراکنش‌ها")
        export.clicked.connect(self.export_transactions_csv)
        row.addWidget(refresh)
        row.addWidget(export)
        row.addStretch()
        l.addLayout(row)
        self.report_label = QLabel()
        self.report_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.report_label.setWordWrap(True)
        l.addWidget(self.report_label)
        l.addStretch()
        self.load_reports()

    def _build_settings(self):
        l = QVBoxLayout(self.settings_tab)
        form = QGroupBox("تنظیمات مزون" if self.role == "maison" else "تنظیمات شخصی")
        f = QFormLayout(form)
        self.business_name = QLineEdit()
        self.currency = QLineEdit()
        f.addRow("نام:", self.business_name)
        f.addRow("واحد پول:", self.currency)
        if self.role == "maison":
            self.instagram = QLineEdit()
            self.birthday_discount = QSpinBox(); self.birthday_discount.setRange(0, 100)
            self.sms_enabled = QCheckBox("بررسی و ارسال خودکار پیامک تولد")
            self.sms_api_url = QLineEdit()
            self.sms_api_key = QLineEdit(); self.sms_api_key.setEchoMode(QLineEdit.EchoMode.Password)
            self.sms_sender = QLineEdit()
            f.addRow("پیج اینستاگرام:", self.instagram)
            f.addRow("تخفیف تولد (%):", self.birthday_discount)
            f.addRow("", self.sms_enabled)
            f.addRow("آدرس API پیامک:", self.sms_api_url)
            f.addRow("کلید API:", self.sms_api_key)
            f.addRow("شماره/فرستنده SMS:", self.sms_sender)
        save = QPushButton("ذخیره تنظیمات")
        save.clicked.connect(self.save_settings)
        f.addRow("", save)
        l.addWidget(form)
        backup = QHBoxLayout()
        for text, slot in [("ایجاد نسخه پشتیبان", self.backup_database), ("بازیابی نسخه پشتیبان", self.restore_database), ("باز کردن پوشه داده", self.open_data_folder)]:
            b = QPushButton(text); b.clicked.connect(slot); backup.addWidget(b)
        backup.addStretch(); l.addLayout(backup)
        auth_box = QGroupBox("تغییر نام کاربری و رمز عبور این حساب")
        af = QFormLayout(auth_box)
        self.auth_current_password = QLineEdit(); self.auth_current_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_new_username = QLineEdit(username_for_role(self.role))
        self.auth_new_password = QLineEdit(); self.auth_new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_repeat_password = QLineEdit(); self.auth_repeat_password.setEchoMode(QLineEdit.EchoMode.Password)
        af.addRow("رمز عبور فعلی:", self.auth_current_password)
        af.addRow("نام کاربری جدید:", self.auth_new_username)
        af.addRow("رمز عبور جدید:", self.auth_new_password)
        af.addRow("تکرار رمز جدید:", self.auth_repeat_password)
        auth_save = QPushButton("تغییر اطلاعات ورود")
        auth_save.clicked.connect(self.change_login_credentials)
        af.addRow("", auth_save)
        l.addWidget(auth_box)
        info_text = "حساب مزون و حساب شخصی دیتابیس جدا دارند.\nIP Address = 192.168.1.4"
        if self.role == "maison": info_text += "\nبررسی تولد مشتریان و ارسال پیامک فقط در حساب مزون فعال است."
        l.addWidget(QLabel(info_text)); l.addStretch()

    def _load_settings(self):
        r = self.db.conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        if not r: return
        self.business_name.setText(r["business_name"] or ("مزون من" if self.role == "maison" else "حسابداری شخصی"))
        self.currency.setText(r["currency"] or "تومان")
        if self.role == "maison":
            self.instagram.setText(r["instagram"] or "")
            self.birthday_discount.setValue(int(r["birthday_discount"] or 20))
            self.sms_enabled.setChecked(bool(r["sms_enabled"]))
            self.sms_api_url.setText(r["sms_api_url"] or "")
            self.sms_api_key.setText(r["sms_api_key"] or "")
            self.sms_sender.setText(r["sms_sender"] or "")

    def save_settings(self):
        if self.role == "maison":
            self.db.conn.execute("""UPDATE settings SET business_name=?, currency=?, instagram=?, birthday_discount=?, sms_enabled=?, sms_api_url=?, sms_api_key=?, sms_sender=? WHERE id=1""", (
                self.business_name.text().strip() or "مزون من", self.currency.text().strip() or "تومان", self.instagram.text().strip(), self.birthday_discount.value(),
                1 if self.sms_enabled.isChecked() else 0, self.sms_api_url.text().strip(), self.sms_api_key.text().strip(), self.sms_sender.text().strip()))
        else:
            self.db.conn.execute("UPDATE settings SET business_name=?, currency=? WHERE id=1", (self.business_name.text().strip() or "حسابداری شخصی", self.currency.text().strip() or "تومان"))
        self.db.conn.commit(); self.db.log("تغییر تنظیمات", self.business_name.text().strip())
        QMessageBox.information(self, "انجام شد", "تنظیمات ذخیره شد."); self.refresh_all()

    def change_login_credentials(self):
        current = self.auth_current_password.text()
        new_username = self.auth_new_username.text().strip()
        new_password = self.auth_new_password.text()
        repeated = self.auth_repeat_password.text()
        if new_password != repeated:
            QMessageBox.warning(self, "خطا", "رمز عبور جدید و تکرار آن یکسان نیستند.")
            return
        if not current or not new_password:
            QMessageBox.warning(self, "خطا", "رمز فعلی و رمز جدید را وارد کنید.")
            return
        ok, message = change_credentials(self.role, current, new_username, new_password)
        if ok:
            self.auth_current_password.clear(); self.auth_new_password.clear(); self.auth_repeat_password.clear()
            self.auth_new_username.setText(new_username)
            self.db.log("تغییر اطلاعات ورود", self.role)
            QMessageBox.information(self, "انجام شد", message)
        else:
            QMessageBox.warning(self, "خطا", message)

    def add_transaction(self):
        title = self.tx_title.text().strip()
        if not title:
            QMessageBox.warning(self, "خطا", "عنوان تراکنش را وارد کنید.")
            return
        try:
            amount = parse_amount(self.tx_amount.text())
        except InvalidOperation:
            QMessageBox.warning(self, "خطا", "مبلغ معتبر نیست.")
            return
        party_id = self.party_id_by_name(self.tx_party.currentText())
        self.db.conn.execute("""
            INSERT INTO transactions(tx_type,title,amount,tx_date,party_id,description,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (
            "income" if self.tx_type.currentText() == "درآمد" else "expense",
            title, amount, self.tx_date.date().toString("yyyy-MM-dd"),
            party_id, self.tx_description.text().strip(), now_text()
        ))
        self.db.conn.commit()
        self.db.log("ثبت تراکنش", title)
        self.clear_tx_form()
        self.refresh_all()

    def clear_tx_form(self):
        self.tx_title.clear()
        self.tx_amount.clear()
        self.tx_description.clear()
        self.tx_type.setCurrentIndex(0)

    def delete_transaction(self):
        row = self.tx_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "خطا", "یک تراکنش را انتخاب کنید.")
            return
        tx_id = en_digits(self.tx_table.item(row, 0).text())
        if QMessageBox.question(self, "تأیید", "این تراکنش حذف شود؟") != QMessageBox.StandardButton.Yes:
            return
        self.db.conn.execute("DELETE FROM transactions WHERE id=?", (tx_id,))
        self.db.conn.commit()
        self.db.log("حذف تراکنش", tx_id)
        self.refresh_all()

    def add_party(self):
        name = self.p_name.text().strip()
        if not name:
            QMessageBox.warning(self, "خطا", "نام را وارد کنید.")
            return
        birth = None
        if self.role == "maison":
            birth = None if self.p_birth_optional.isChecked() else self.p_birth.date().toString("yyyy-MM-dd")
        self.db.conn.execute("""
            INSERT INTO parties(name,phone,national_id,address,notes,birth_date,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (
            name, self.p_phone.text().strip(), self.p_national.text().strip(),
            self.p_address.text().strip(), self.p_notes.text().strip(),
            birth or None, now_text()
        ))
        self.db.conn.commit()
        self.db.log("ثبت طرف حساب", name)
        for w in (self.p_name, self.p_phone, self.p_national, self.p_address, self.p_notes):
            w.clear()
        if self.role == "maison":
            self.p_birth.setDate(QDate.currentDate())
            self.p_birth_optional.setChecked(True)
        self.refresh_all()

    def delete_party(self):
        row = self.party_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "خطا", "یک طرف حساب را انتخاب کنید.")
            return
        pid = en_digits(self.party_table.item(row, 0).text())
        if QMessageBox.question(self, "تأیید", "طرف حساب حذف شود؟") != QMessageBox.StandardButton.Yes:
            return
        self.db.conn.execute("DELETE FROM parties WHERE id=?", (pid,))
        self.db.conn.commit()
        self.db.log("حذف طرف حساب", pid)
        self.refresh_all()

    def add_invoice_item(self):
        name = self.inv_item_name.text().strip()
        if not name:
            QMessageBox.warning(self, "خطا", "نام کالا/خدمت را وارد کنید."); return
        try:
            qty = float(en_digits(self.inv_item_qty.text()).replace(",", ""))
            price = parse_amount(self.inv_item_price.text())
            if qty <= 0: raise ValueError
        except (ValueError, InvalidOperation):
            QMessageBox.warning(self, "خطا", "تعداد یا قیمت معتبر نیست."); return
        row = self.inv_items.rowCount(); self.inv_items.insertRow(row)
        total = int(qty * price)
        for col, val in enumerate([name, fa_digits(qty), money(price), money(total), "حذف"]):
            self.inv_items.setItem(row, col, QTableWidgetItem(str(val)))
        self.inv_items.item(row, 4).setData(Qt.ItemDataRole.UserRole, row)
        self.inv_item_name.clear(); self.inv_item_qty.setText("1"); self.inv_item_price.setText("0")

    def remove_invoice_item(self, row):
        if 0 <= row < self.inv_items.rowCount(): self.inv_items.removeRow(row)

    def add_invoice(self):
        no = self.inv_no.text().strip()
        if not no:
            QMessageBox.warning(self, "خطا", "شماره فاکتور را وارد کنید."); return
        try:
            discount = parse_amount(self.inv_discount.text()); paid = parse_amount(self.inv_paid.text())
        except InvalidOperation:
            QMessageBox.warning(self, "خطا", "تخفیف یا مبلغ پرداخت معتبر نیست."); return
        pid = self.party_id_by_name(self.inv_party.currentText())
        try:
            cur = self.db.conn.cursor()
            cur.execute("INSERT INTO invoices(invoice_no,invoice_type,party_id,invoice_date,discount,paid,notes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (no, "sale" if self.inv_type.currentText() == "فروش" else "purchase", pid, self.inv_date.date().toString("yyyy-MM-dd"), discount, paid, self.inv_notes.text().strip(), now_text()))
            iid = cur.lastrowid
            for row in range(self.inv_items.rowCount()):
                name = self.inv_items.item(row,0).text()
                qty = float(en_digits(self.inv_items.item(row,1).text()).replace(",", ""))
                price = int(en_digits(self.inv_items.item(row,2).text()).replace(",", ""))
                cur.execute("INSERT INTO invoice_items(invoice_id,item_name,quantity,unit_price) VALUES(?,?,?,?)", (iid,name,qty,price))
            self.db.conn.commit()
        except sqlite3.IntegrityError:
            self.db.conn.rollback(); QMessageBox.warning(self, "خطا", "شماره فاکتور تکراری است."); return
        self.db.log("ثبت فاکتور", no)
        self.inv_no.clear(); self.inv_discount.setText("0"); self.inv_paid.setText("0"); self.inv_notes.clear(); self.inv_items.setRowCount(0)
        self.load_invoices()

    def delete_invoice(self):
        row = self.invoice_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "خطا", "یک فاکتور را انتخاب کنید.")
            return
        iid = en_digits(self.invoice_table.item(row, 0).text())
        if QMessageBox.question(self, "تأیید", "این فاکتور حذف شود؟") != QMessageBox.StandardButton.Yes:
            return
        self.db.conn.execute("DELETE FROM invoices WHERE id=?", (iid,))
        self.db.conn.commit()
        self.db.log("حذف فاکتور", iid)
        self.refresh_all()

    def delete_asset(self):
        row = self.asset_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "خطا", "یک دارایی را انتخاب کنید.")
            return
        aid = en_digits(self.asset_table.item(row, 0).text())
        if QMessageBox.question(self, "تأیید", "این دارایی حذف شود؟") != QMessageBox.StandardButton.Yes:
            return
        self.db.conn.execute("DELETE FROM assets WHERE id=?", (aid,))
        self.db.conn.commit()
        self.db.log("حذف دارایی", aid)
        self.refresh_all()

    def add_asset(self):
        name = self.asset_name.text().strip()
        if not name:
            QMessageBox.warning(self, "خطا", "نام دارایی را وارد کنید.")
            return
        try:
            qty = float(en_digits(self.asset_qty.text()).replace(",", ""))
            if qty < 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "خطا", "مقدار دارایی معتبر نیست.")
            return
        self.db.conn.execute("""
            INSERT INTO assets(name,asset_type,quantity,unit,note,created_at)
            VALUES(?,?,?,?,?,?)
        """, (name, self.asset_type.currentText(), qty, self.asset_unit.text().strip() or "عدد",
              self.asset_note.text().strip(), now_text()))
        self.db.conn.commit()
        self.db.log("ثبت دارایی", name)
        self.asset_name.clear()
        self.asset_qty.setText("0")
        self.asset_note.clear()
        self.load_assets()

    def party_id_by_name(self, name):
        if not name or name == "بدون طرف حساب":
            return None
        r = self.db.conn.execute("SELECT id FROM parties WHERE name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        return r["id"] if r else None

    def refresh_party_combos(self):
        rows = self.db.conn.execute("SELECT id,name FROM parties ORDER BY name").fetchall()
        names = ["بدون طرف حساب"] + [r["name"] for r in rows]
        for combo in (self.tx_party, self.inv_party):
            current = combo.currentText()
            combo.clear()
            combo.addItems(names)
            if current in names:
                combo.setCurrentText(current)

    def load_dashboard(self):
        inc = self.db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='income'").fetchone()["x"]
        exp = self.db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='expense'").fetchone()["x"]
        pc = self.db.conn.execute("SELECT COUNT(*) x FROM parties").fetchone()["x"]
        self.income_card.value.setText(money(inc))
        self.expense_card.value.setText(money(exp))
        self.balance_card.value.setText(money(int(inc) - int(exp)))
        self.party_card.value.setText(fa_digits(pc))
        self.dashboard_table.setRowCount(0)
        rows = self.db.conn.execute("""
            SELECT id,tx_type,title,amount,tx_date FROM transactions ORDER BY id DESC LIMIT 15
        """).fetchall()
        for r in rows:
            self._add_row(self.dashboard_table, [
                fa_digits(r["id"]), "درآمد" if r["tx_type"] == "income" else "هزینه",
                r["title"], money(r["amount"]), fa_digits(jalali_display_from_iso(r["tx_date"]))
            ])

    def load_transactions(self):
        self.tx_table.setRowCount(0)
        s = self.tx_search.text().strip() if hasattr(self, "tx_search") else ""
        q = """
            SELECT t.id,t.tx_type,t.title,t.amount,t.tx_date,
                   COALESCE(p.name,'بدون طرف حساب') party,t.description
            FROM transactions t LEFT JOIN parties p ON p.id=t.party_id
        """
        params = []
        if s:
            q += """ WHERE t.title LIKE ? OR t.description LIKE ? OR p.name LIKE ? """
            like = f"%{s}%"
            params = [like, like, like]
        q += " ORDER BY t.id DESC"
        for r in self.db.conn.execute(q, params).fetchall():
            self._add_row(self.tx_table, [
                fa_digits(r["id"]), "درآمد" if r["tx_type"] == "income" else "هزینه",
                r["title"], money(r["amount"]), fa_digits(jalali_display_from_iso(r["tx_date"])),
                r["party"], r["description"] or ""
            ])

    def load_parties(self):
        self.party_table.setRowCount(0)
        for r in self.db.conn.execute("SELECT id,name,phone,national_id,address,birth_date,notes FROM parties ORDER BY id DESC").fetchall():
            values = [fa_digits(r["id"]), r["name"], r["phone"] or "", r["national_id"] or "", r["address"] or ""]
            values += ([jalali_display_from_iso(r["birth_date"]) if r["birth_date"] else "", r["notes"] or ""] if self.role == "maison" else [r["notes"] or ""])
            self._add_row(self.party_table, values)

    def load_invoices(self):
        self.invoice_table.setRowCount(0)
        rows = self.db.conn.execute("""SELECT i.id,i.invoice_no,i.invoice_type,COALESCE(p.name,'بدون طرف حساب') party,i.invoice_date,i.discount,i.paid,COALESCE((SELECT SUM(ii.quantity*ii.unit_price) FROM invoice_items ii WHERE ii.invoice_id=i.id),0) item_total FROM invoices i LEFT JOIN parties p ON p.id=i.party_id ORDER BY i.id DESC""").fetchall()
        for r in rows:
            self._add_row(self.invoice_table, [fa_digits(r["id"]), r["invoice_no"], "فروش" if r["invoice_type"] == "sale" else "خرید", r["party"], jalali_display_from_iso(r["invoice_date"]), money(r["item_total"]), money(r["discount"]), money(r["paid"])])

    def load_assets(self):
        self.asset_table.setRowCount(0)
        for r in self.db.conn.execute("SELECT id,name,asset_type,quantity,unit,note FROM assets ORDER BY id DESC").fetchall():
            self._add_row(self.asset_table, [
                fa_digits(r["id"]), r["name"], r["asset_type"],
                fa_digits(r["quantity"]), r["unit"], r["note"] or ""
            ])

    def load_reports(self):
        inc = self.db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='income'").fetchone()["x"]
        exp = self.db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='expense'").fetchone()["x"]
        inv = self.db.conn.execute("SELECT COUNT(*) x FROM invoices").fetchone()["x"]
        parties = self.db.conn.execute("SELECT COUNT(*) x FROM parties").fetchone()["x"]
        self.report_label.setText(
            f"گزارش کلی\n\n"
            f"مجموع درآمد: {money(inc)} {self.currency.text() if hasattr(self,'currency') else 'تومان'}\n"
            f"مجموع هزینه: {money(exp)}\n"
            f"سود/مانده: {money(int(inc)-int(exp))}\n"
            f"تعداد فاکتورها: {fa_digits(inv)}\n"
            f"تعداد طرف حساب‌ها: {fa_digits(parties)}"
        )

    def load_birthdays(self):
        self.birthday_table.setRowCount(0)
        today_j = QCalendar(QCalendar.System.Jalali).partsFromDate(QDate.currentDate())
        today_md = (today_j.month, today_j.day)
        rows = self.db.conn.execute("""
            SELECT id,name,phone,birth_date FROM parties
            WHERE birth_date IS NOT NULL AND birth_date != ''
        """).fetchall()
        discount = self.birthday_discount.value()
        year = today_j.year
        for r in rows:
            if jalali_month_day_from_iso(r["birth_date"]) == today_md:
                sent = self.db.conn.execute(
                    "SELECT status FROM birthday_sms_log WHERE party_id=? AND birthday_year=?",
                    (r["id"], year)
                ).fetchone()
                status = "ثبت‌شده" if sent else "آماده ارسال"
                self._add_row(self.birthday_table, [r["name"], r["phone"] or "", f"{discount}٪", status])

    def send_birthday_sms(self, party_id, phone, name):
        api_url = self.sms_api_url.text().strip()
        api_key = self.sms_api_key.text().strip()
        sender = self.sms_sender.text().strip()
        if not api_url or not api_key or not phone:
            return False, "API، کلید API یا شماره موبایل ناقص است"
        message = (
            f"تولدتان مبارک {name} 🎂\n"
            f"به مناسبت تولدتان {self.birthday_discount.value()}٪ تخفیف ویژه دارید.\n"
            f"{self.instagram.text().strip()}"
        ).strip()
        try:
            url = api_url.format(
                api_key=api_key, receptor=phone, phone=phone,
                message=message, sender=sender, name=name
            )
            if "?" in url:
                url += "&" + urlencode({"receptor": phone, "message": message, "sender": sender})
            else:
                url += "?" + urlencode({"receptor": phone, "message": message, "sender": sender})
            req = Request(url, headers={"User-Agent": "HesabdariMezon/1.0"})
            with urlopen(req, timeout=15) as response:
                if 200 <= response.status < 300:
                    return True, "ارسال شد"
                return False, f"HTTP {response.status}"
        except Exception as exc:
            return False, str(exc)[:120]

    def send_selected_birthday_sms(self):
        if self.role != "maison": return
        row = self.birthday_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "خطا", "یک مشتری از فهرست تولدهای امروز انتخاب کنید."); return
        name = self.birthday_table.item(row, 0).text()
        r = self.db.conn.execute("SELECT id,name,phone FROM parties WHERE name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        if not r:
            QMessageBox.warning(self, "خطا", "مشتری پیدا نشد."); return
        ok, status = self.send_birthday_sms(r["id"], r["phone"], r["name"])
        QMessageBox.information(self, "پیامک", status if ok else "ارسال انجام نشد: " + status)
        self.load_birthdays()

    def check_birthdays(self):
        self.load_birthdays()
        if not self.sms_enabled.isChecked():
            return
        today_j = QCalendar(QCalendar.System.Jalali).partsFromDate(QDate.currentDate())
        today_year = today_j.year
        today_md = (today_j.month, today_j.day)
        rows = self.db.conn.execute(
            "SELECT id,name,phone,birth_date FROM parties WHERE birth_date IS NOT NULL AND birth_date != ''"
        ).fetchall()
        for r in rows:
            if jalali_month_day_from_iso(r["birth_date"]) != today_md or not r["phone"]:
                continue
            exists = self.db.conn.execute(
                "SELECT 1 FROM birthday_sms_log WHERE party_id=? AND birthday_year=?",
                (r["id"], today_year)
            ).fetchone()
            if exists:
                continue
            ok, status = self.send_birthday_sms(r["id"], r["phone"], r["name"])
            self.db.conn.execute(
                "INSERT OR IGNORE INTO birthday_sms_log(party_id,birthday_year,status,sent_at) VALUES(?,?,?,?)",
                (r["id"], today_year, "ارسال شد" if ok else "خطا: " + status, now_text())
            )
            self.db.conn.commit()
        self.load_birthdays()

    def refresh_all(self):
        self.refresh_party_combos()
        self.load_dashboard()
        self.load_transactions()
        self.load_parties()
        self.load_invoices()
        self.load_assets()
        self.load_reports()
        if self.role == "maison":
            self.load_birthdays()

    def _add_row(self, table, values):
        row = table.rowCount()
        table.insertRow(row)
        for col, value in enumerate(values):
            table.setItem(row, col, QTableWidgetItem(str(value)))

    def export_transactions_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "ذخیره CSV تراکنش‌ها",
            "transactions.csv",
            "CSV (*.csv)"
        )
        if not path:
            return

        rows = self.db.conn.execute("""
            SELECT
                t.id,
                t.tx_type,
                t.title,
                t.amount,
                t.tx_date,
                COALESCE(p.name, ''),
                COALESCE(t.description, '')
            FROM transactions t
            LEFT JOIN parties p ON p.id = t.party_id
            ORDER BY t.id
        """).fetchall()

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([
                "شناسه",
                "نوع",
                "عنوان",
                "مبلغ",
                "تاریخ",
                "طرف حساب",
                "توضیحات"
            ])

            for r in rows:
                tx_type = "درآمد" if r[1] == "income" else "هزینه"
                date_text = jalali_display_from_iso(r[4]) if r[4] else ""
                w.writerow([
                    r[0],
                    tx_type,
                    r[2],
                    r[3],
                    date_text,
                    r[5],
                    r[6]
                ])

        QMessageBox.information(
            self,
            "انجام شد",
            f"خروجی CSV تراکنش‌ها با موفقیت ذخیره شد.\n\n{path}"
        )

    def export_parties_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "ذخیره CSV", "parties.csv", "CSV (*.csv)")
        if not path:
            return
        rows = self.db.conn.execute("SELECT id,name,phone,national_id,address,birth_date,notes FROM parties").fetchall()
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["id","name","phone","national_id","address","birth_date","notes"])
            for r in rows:
                w.writerow(list(r))
        QMessageBox.information(self, "انجام شد", "فایل CSV ذخیره شد.")

    def backup_database(self):
        path, _ = QFileDialog.getSaveFileName(self, "ذخیره پشتیبان", "hesabdari_backup.db", "Database (*.db)")
        if not path:
            return
        self.db.conn.commit()
        shutil.copy2(self.db_path, path)
        QMessageBox.information(self, "پشتیبان‌گیری", "نسخه پشتیبان ساخته شد.")

    def restore_database(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب پشتیبان", "", "Database (*.db)")
        if not path:
            return
        if QMessageBox.question(self, "هشدار", "اطلاعات فعلی جایگزین شود؟") != QMessageBox.StandardButton.Yes:
            return
        self.db.close()
        shutil.copy2(path, self.db_path)
        self.db = Database(self.db_path)
        self._load_settings()
        self.refresh_all()
        QMessageBox.information(self, "بازیابی", "اطلاعات بازیابی شد.")

    def open_data_folder(self):
        folder = str(APP_DATA_DIR)
        if sys.platform.startswith("win"):
            os.startfile(folder)
        elif sys.platform == "darwin":
            os.system(f'open "{folder}"')
        else:
            os.system(f'xdg-open "{folder}"')

    def closeEvent(self, event):
        try:
            if getattr(self, "web_server", None):
                self.web_server.stop()
            self.db.close()
        finally:
            event.accept()


class LocalWebServer:
    def __init__(self, window):
        self.window = window
        self.server = None
        self.thread = None
        self.sessions = {}
        self.session_lock = threading.Lock()

    def start(self):
        parent = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def session(self):
                cookie = self.headers.get("Cookie", "")
                token = ""
                for part in cookie.split(";"):
                    if part.strip().startswith("hesabdari_session="):
                        token = part.strip().split("=", 1)[1]
                with parent.session_lock:
                    return parent.sessions.get(token)

            def db_for(self):
                sess = self.session()
                if not sess:
                    return None, None
                return sess["role"], Database(sess["db_path"])

            def redirect(self, path):
                self.send_response(302)
                self.send_header("Location", path)
                self.end_headers()

            def do_GET(self):
                path = urlparse(self.path).path
                try:
                    if path == "/":
                        self.send_html(parent.login_page())
                        return
                    sess = self.session()
                    if not sess:
                        self.redirect("/")
                        return
                    pages = {
                        "/dashboard": parent.dashboard_page,
                        "/transactions": parent.transactions_page,
                        "/parties": parent.parties_page,
                        "/invoices": parent.invoices_page,
                        "/reports": parent.reports_page,
                        "/settings": parent.settings_page,
                    }
                    if sess["role"] == "maison":
                        pages["/birthdays"] = parent.birthdays_page
                    if path == "/assets":
                        self.send_html(parent.assets_page(sess))
                        return
                    page_func = pages.get(path)
                    if page_func is None:
                        self.send_error(404)
                        return
                    self.send_html(page_func(sess))
                except Exception as exc:
                    parent.write_web_error(exc, path)
                    if not self.wfile.closed:
                        self.send_html(parent.error_page("خطا در بارگذاری این بخش: " + html.escape(str(exc))))

            def do_POST(self):
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length", 0))
                data = parse_qs(self.rfile.read(length).decode("utf-8"))
                if path == "/login":
                    u = data.get("username", [""])[0].strip()
                    p = data.get("password", [""])[0]
                    role = authenticate(u, p)
                    if role:
                        token = secrets.token_urlsafe(24)
                        db_path = str(MAISON_DB if role == "maison" else PERSONAL_DB)
                        with parent.session_lock:
                            parent.sessions[token] = {"role": role, "db_path": db_path}
                        self.send_response(302)
                        self.send_header("Location", "/dashboard")
                        self.send_header("Set-Cookie", f"hesabdari_session={token}; HttpOnly; SameSite=Lax; Path=/")
                        self.end_headers()
                    else:
                        self.send_html(parent.login_page("نام کاربری یا رمز عبور اشتباه است."))
                    return
                sess = self.session()
                if not sess:
                    self.redirect("/")
                    return
                if path == "/change_credentials":
                    current_password = data.get("current_password", [""])[0]
                    new_username = data.get("new_username", [""])[0].strip()
                    new_password = data.get("new_password", [""])[0]
                    repeat_password = data.get("repeat_password", [""])[0]
                    if new_password != repeat_password:
                        self.send_html(parent.error_page("رمز جدید و تکرار آن یکسان نیستند.")); return
                    ok, message = change_credentials(sess["role"], current_password, new_username, new_password)
                    if ok:
                        db_log = Database(sess["db_path"])
                        try: db_log.log("تغییر اطلاعات ورود", sess["role"])
                        finally: db_log.close()
                        self.send_html(parent.page("تنظیمات", f"<p>{html.escape(message)}</p><p>اکنون می‌توانید با اطلاعات جدید وارد شوید.</p><a href=\"/settings\">بازگشت به تنظیمات</a>", sess["role"]))
                    else:
                        self.send_html(parent.error_page(html.escape(message)))
                    return
                db = Database(sess["db_path"])
                try:
                    if path == "/transaction":
                        title = data.get("title", [""])[0].strip()
                        amount = parse_amount(data.get("amount", [""])[0])
                        typ = "income" if data.get("type", ["income"])[0] == "income" else "expense"
                        db.conn.execute("INSERT INTO transactions(tx_type,title,amount,tx_date,description,created_at) VALUES(?,?,?,?,?,?)", (typ,title,amount,iso_from_jalali(data.get("date",[jalali_today()])[0]),data.get("description", [""])[0].strip(),now_text()))
                        db.conn.commit()
                        self.redirect("/transactions")
                    elif path == "/delete_transaction":
                        db.conn.execute("DELETE FROM transactions WHERE id=?", (en_digits(data.get("id", [""])[0]),))
                        db.conn.commit(); self.redirect("/transactions")
                    elif path == "/party":
                        name=data.get("name", [""])[0].strip()
                        birth_raw = data.get("birth_date", [""])[0].strip()
                        birth = (iso_from_jalali(birth_raw) if birth_raw else None) if sess["role"] == "maison" else None
                        if name:
                            db.conn.execute("INSERT INTO parties(name,phone,national_id,address,notes,birth_date,created_at) VALUES(?,?,?,?,?,?,?)", (name,data.get("phone", [""])[0].strip(),data.get("national_id", [""])[0].strip(),data.get("address", [""])[0].strip(),data.get("notes", [""])[0].strip(),birth,now_text())); db.conn.commit()
                        self.redirect("/parties")
                    elif path == "/delete_party":
                        db.conn.execute("DELETE FROM parties WHERE id=?", (en_digits(data.get("id", [""])[0]),)); db.conn.commit(); self.redirect("/parties")
                    elif path == "/invoice":
                        no=data.get("invoice_no", [""])[0].strip()
                        if no:
                            db.conn.execute("INSERT INTO invoices(invoice_no,invoice_type,invoice_date,discount,paid,notes,created_at) VALUES(?,?,?,?,?,?,?)", (no,"sale" if data.get("type",["sale"])[0]=="sale" else "purchase",iso_from_jalali(data.get("date",[jalali_today()])[0]),parse_amount(data.get("discount",["0"])[0]),parse_amount(data.get("paid",["0"])[0]),data.get("notes",[""])[0].strip(),now_text())); db.conn.commit()
                        self.redirect("/invoices")
                    elif path == "/delete_invoice":
                        db.conn.execute("DELETE FROM invoices WHERE id=?", (en_digits(data.get("id", [""])[0]),)); db.conn.commit(); self.redirect("/invoices")
                    elif path == "/asset":
                        asset_name = data.get("name", [""])[0].strip()
                        asset_type = data.get("type", ["سایر"])[0]
                        allowed_types = ({"تجهیزات فروشگاه پوشاک", "تجهیزات کارگاه خیاطی", "سایر تجهیزات مزون"}
                                         if sess["role"] == "maison" else
                                         {"نقد", "بانک", "طلا", "دلار", "سکه", "ارز", "ملک", "خودرو", "سهام", "کریپتو", "تجهیزات", "سایر"})
                        if asset_name and asset_type in allowed_types:
                            quantity = float(en_digits(data.get("quantity", ["0"])[0]).replace(",", ""))
                            if quantity >= 0:
                                db.conn.execute("INSERT INTO assets(name,asset_type,quantity,unit,note,created_at) VALUES(?,?,?,?,?,?)", (asset_name, asset_type, quantity, data.get("unit", ["عدد"])[0].strip() or "عدد", data.get("note", [""])[0].strip(), now_text()))
                                db.conn.commit()
                        self.redirect("/assets")
                    elif path == "/delete_asset":
                        db.conn.execute("DELETE FROM assets WHERE id=?", (en_digits(data.get("id", [""])[0]),)); db.conn.commit(); self.redirect("/assets")
                    elif path == "/settings":
                        if sess["role"] == "maison":
                            db.conn.execute("UPDATE settings SET business_name=?,currency=?,instagram=?,birthday_discount=?,sms_enabled=?,sms_api_url=?,sms_api_key=?,sms_sender=? WHERE id=1", (data.get("business_name",[""])[0].strip(),data.get("currency",["تومان"])[0].strip(),data.get("instagram",[""])[0].strip(),int(data.get("discount",["20"])[0]),1 if data.get("sms_enabled",[""])[0] else 0,data.get("api_url",[""])[0].strip(),data.get("api_key",[""])[0].strip(),data.get("sender",[""])[0].strip()))
                        else:
                            db.conn.execute("UPDATE settings SET business_name=?,currency=? WHERE id=1", (data.get("business_name",[""])[0].strip(),data.get("currency",["تومان"])[0].strip()))
                        db.conn.commit(); self.redirect("/settings")
                    else:
                        self.send_error(404)
                except Exception as exc:
                    self.send_html(parent.error_page(str(exc)))
                finally:
                    db.close()

            def send_html(self, html):
                raw = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        try:
            self.server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
        except OSError:
            self.server = ThreadingHTTPServer((WEB_HOST, 0), Handler)
        port = self.server.server_address[1]
        self.port = port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # نمایش ثابت نشانی موردنظر کاربر؛ سرویس داخلی همچنان روی پورت WEB_PORT اجرا می‌شود.
        self.window.web_label.setText("IP Address = 192.168.1.4")

    def write_web_error(self, exc, path):
        try:
            log_path = APP_DATA_DIR / "web_error.log"
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{now_text()}] {path}: {type(exc).__name__}: {exc}\n")
        except Exception:
            pass

    def stop(self):
        if self.server:
            self.server.shutdown(); self.server.server_close()

    @staticmethod
    def tailscale_ip():
        import socket
        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip.startswith("100."):
                    return ip
        except Exception:
            pass
        try:
            _, _, ips = socket.gethostbyname_ex(socket.gethostname())
            for ip in ips:
                if ip.startswith("100."):
                    return ip
        except Exception:
            pass
        return None

    @staticmethod
    def local_ip():
        import socket
        # اول IPهای واقعی شبکه محلی را از کارت‌های شبکه پیدا می‌کنیم.
        # این روش به اینترنت یا DNS گوگل وابسته نیست و برای شبکه داخلی مناسب‌تر است.
        candidates = []
        try:
            hostname = socket.gethostname()
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    candidates.append(ip)
        except Exception:
            pass

        try:
            _, _, ips = socket.gethostbyname_ex(socket.gethostname())
            for ip in ips:
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    candidates.append(ip)
        except Exception:
            pass

        # اگر IP ترجیحی در فهرست رابط‌های واقعی همین کامپیوتر باشد، همان را نمایش بده.
        # به‌این‌ترتیب لینک ثابت ترجیح داده می‌شود، اما IP اشتباه/غیرفعال نمایش داده نمی‌شود.
        if PREFERRED_LOCAL_IP and PREFERRED_LOCAL_IP in candidates:
            return PREFERRED_LOCAL_IP

        # اگر IP ترجیحی روی این کامپیوتر تنظیم نشده باشد، IP واقعی را خودکار پیدا کن.
        for prefix in ("192.168.", "10.", "172."):
            for ip in candidates:
                if ip.startswith(prefix):
                    return ip

        if candidates:
            return candidates[0]

        return "127.0.0.1"

    @staticmethod
    def css():
        return '''body{font-family:Tahoma,Arial;background:#071b3a;color:#fff;margin:0;padding:16px}main{max-width:1000px;margin:auto}.box{max-width:420px;margin:40px auto;background:#102a50;padding:24px;border-radius:18px}input,select,button{width:100%;box-sizing:border-box;padding:12px;margin:5px 0;border-radius:10px;border:0}button{background:#d4af37;color:#111;font-weight:bold}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.card{background:#102a50;border-radius:14px;padding:16px}.nav{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:12px 0}.nav a{background:#102a50;color:#fff;text-decoration:none;padding:11px;border-radius:10px;text-align:center}table{width:100%;border-collapse:collapse;background:#102a50;margin-top:12px}th,td{padding:8px;border-bottom:1px solid #29466f;text-align:right}a{color:#ffd85a}.danger{background:#9b2226;color:white}.muted{opacity:.8}@media(min-width:700px){.grid{grid-template-columns:repeat(4,1fr)}.nav{grid-template-columns:repeat(4,1fr)}}'''

    def page(self, title, body, role):
        asset = '<a href="/assets">🧰 دارایی‌ها</a>'
        birthday = '<a href="/birthdays">🎂 تولدها</a>' if role == 'maison' else ''
        nav = f'<div class="nav"><a href="/dashboard">🏠 داشبورد</a><a href="/transactions">💰 درآمد و هزینه</a><a href="/parties">👥 طرف حساب‌ها</a><a href="/invoices">🧾 فاکتورها</a>{asset}<a href="/reports">📊 گزارش‌ها</a>{birthday}<a href="/settings">⚙️ تنظیمات</a></div>'
        return f'<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>{self.css()}</style><body><main><h1>{title}</h1>{nav}{body}</main></body></html>'

    def login_page(self, error=""):
        return f'<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>{self.css()}</style><body><main class="box"><h1>حسابداری</h1><p>ورود به نسخه موبایل</p><form method="post" action="/login"><input name="username" placeholder="نام کاربری" required><input name="password" type="password" placeholder="رمز عبور" required><button>ورود</button></form><p>{error}</p></main></body></html>'

    def dashboard_page(self, sess):
        db = Database(sess['db_path'])
        try:
            inc = db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='income'").fetchone()['x']
            exp = db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='expense'").fetchone()['x']
            parties = db.conn.execute("SELECT COUNT(*) x FROM parties").fetchone()['x']
            body = f'<div class="grid"><div class="card">درآمد<br><b>{money(inc)}</b></div><div class="card">هزینه<br><b>{money(exp)}</b></div><div class="card">مانده<br><b>{money(int(inc)-int(exp))}</b></div><div class="card">طرف حساب<br><b>{fa_digits(parties)}</b></div></div><h2>ثبت سریع تراکنش</h2><form method="post" action="/transaction"><select name="type"><option value="income">درآمد</option><option value="expense">هزینه</option></select><input name="title" placeholder="عنوان" required><input name="amount" placeholder="مبلغ" required><input name="date" value="{jalali_today()}"><input name="description" placeholder="توضیحات"><button>ثبت</button></form>'
            return self.page('داشبورد حسابداری', body, sess['role'])
        finally:
            db.close()

    def transactions_page(self,sess):
        db=Database(sess['db_path']); rows=db.conn.execute("SELECT id,tx_type,title,amount,tx_date FROM transactions ORDER BY id DESC").fetchall(); db.close()
        trs=''.join(f'<tr><td>{fa_digits(r["id"])}</td><td>{"درآمد" if r["tx_type"]=="income" else "هزینه"}</td><td>{r["title"]}</td><td>{money(r["amount"])}</td><td>{jalali_display_from_iso(r["tx_date"])}</td><td><form method="post" action="/delete_transaction"><input type="hidden" name="id" value="{r["id"]}"><button class="danger">حذف</button></form></td></tr>' for r in rows)
        body=f'<form method="post" action="/transaction"><select name="type"><option value="income">درآمد</option><option value="expense">هزینه</option></select><input name="title" placeholder="عنوان" required><input name="amount" placeholder="مبلغ" required><input name="date" value="{jalali_today()}"><input name="description" placeholder="توضیحات"><button>ثبت تراکنش</button></form><table><tr><th>شناسه</th><th>نوع</th><th>عنوان</th><th>مبلغ</th><th>تاریخ</th><th>عملیات</th></tr>{trs or "<tr><td colspan=6>موردی نیست</td></tr>"}</table>'
        return self.page('درآمد و هزینه',body,sess['role'])

    def parties_page(self,sess):
        db=Database(sess['db_path']); rows=db.conn.execute("SELECT id,name,phone,birth_date,notes FROM parties ORDER BY id DESC").fetchall(); db.close()
        if sess['role'] == 'maison':
            trs=''.join(f'<tr><td>{fa_digits(r["id"])}</td><td>{r["name"]}</td><td>{r["phone"] or ""}</td><td>{jalali_display_from_iso(r["birth_date"]) if r["birth_date"] else ""}</td><td><form method="post" action="/delete_party"><input type="hidden" name="id" value="{r["id"]}"><button class="danger">حذف</button></form></td></tr>' for r in rows)
            body=f'<form method="post" action="/party"><input name="name" placeholder="نام" required><input name="phone" placeholder="موبایل"><input name="national_id" placeholder="کد ملی"><input name="address" placeholder="آدرس"><input name="birth_date" placeholder="تاریخ تولد شمسی 1405/07/09"><input name="notes" placeholder="یادداشت"><button>ثبت طرف حساب</button></form><table><tr><th>شناسه</th><th>نام</th><th>موبایل</th><th>تولد</th><th>عملیات</th></tr>{trs or "<tr><td colspan=5>موردی نیست</td></tr>"}</table>'
        else:
            trs=''.join(f'<tr><td>{fa_digits(r["id"])}</td><td>{r["name"]}</td><td>{r["phone"] or ""}</td><td>{r["notes"] or ""}</td><td><form method="post" action="/delete_party"><input type="hidden" name="id" value="{r["id"]}"><button class="danger">حذف</button></form></td></tr>' for r in rows)
            body=f'<form method="post" action="/party"><input name="name" placeholder="نام" required><input name="phone" placeholder="موبایل"><input name="national_id" placeholder="کد ملی"><input name="address" placeholder="آدرس"><input name="notes" placeholder="یادداشت"><button>ثبت طرف حساب</button></form><table><tr><th>شناسه</th><th>نام</th><th>موبایل</th><th>یادداشت</th><th>عملیات</th></tr>{trs or "<tr><td colspan=5>موردی نیست</td></tr>"}</table>'
        return self.page('طرف حساب‌ها',body,sess['role'])

    def invoices_page(self,sess):
        db=Database(sess['db_path']); rows=db.conn.execute("SELECT id,invoice_no,invoice_type,invoice_date,discount,paid FROM invoices ORDER BY id DESC").fetchall(); db.close()
        trs=''.join(f'<tr><td>{fa_digits(r["id"])}</td><td>{r["invoice_no"]}</td><td>{"فروش" if r["invoice_type"]=="sale" else "خرید"}</td><td>{jalali_display_from_iso(r["invoice_date"])}</td><td>{money(r["discount"])}</td><td>{money(r["paid"])}</td><td><form method="post" action="/delete_invoice"><input type="hidden" name="id" value="{r["id"]}"><button class="danger">حذف</button></form></td></tr>' for r in rows)
        body=f'<form method="post" action="/invoice"><input name="invoice_no" placeholder="شماره فاکتور" required><select name="type"><option value="sale">فروش</option><option value="purchase">خرید</option></select><input name="date" value="{jalali_today()}"><input name="discount" value="0" placeholder="تخفیف"><input name="paid" value="0" placeholder="دریافت/پرداخت"><input name="notes" placeholder="یادداشت"><button>ثبت فاکتور</button></form><table><tr><th>شناسه</th><th>شماره</th><th>نوع</th><th>تاریخ</th><th>تخفیف</th><th>پرداخت</th><th>عملیات</th></tr>{trs or "<tr><td colspan=7>موردی نیست</td></tr>"}</table>'
        return self.page('فاکتورها',body,sess['role'])

    def assets_page(self,sess):
        db=Database(sess['db_path'])
        try:
            rows=db.conn.execute("SELECT id,name,asset_type,quantity,unit,note FROM assets ORDER BY id DESC").fetchall()
        finally:
            db.close()
        trs=''.join(f'<tr><td>{fa_digits(r["id"])}</td><td>{html.escape(str(r["name"]))}</td><td>{html.escape(str(r["asset_type"]))}</td><td>{fa_digits(r["quantity"])} {html.escape(str(r["unit"]))}</td><td>{html.escape(str(r["note"] or ""))}</td><td><form method="post" action="/delete_asset"><input type="hidden" name="id" value="{r["id"]}"><button class="danger">حذف</button></form></td></tr>' for r in rows)
        if sess['role'] == 'maison':
            title = 'دارایی‌های مزون'
            types = '<option>تجهیزات فروشگاه پوشاک</option><option>تجهیزات کارگاه خیاطی</option><option>سایر تجهیزات مزون</option>'
            placeholder = 'نام تجهیز مزون'
        else:
            title = 'دارایی‌های شخصی'
            types = '<option>نقد</option><option>بانک</option><option>طلا</option><option>دلار</option><option>سکه</option><option>ارز</option><option>ملک</option><option>خودرو</option><option>سهام</option><option>کریپتو</option><option>تجهیزات</option><option>سایر</option>'
            placeholder = 'نام دارایی'
        body=f'<form method="post" action="/asset"><input name="name" placeholder="{placeholder}" required><select name="type">{types}</select><input name="quantity" value="1" placeholder="مقدار"><input name="unit" value="عدد" placeholder="واحد"><input name="note" placeholder="یادداشت"><button>ثبت دارایی</button></form><table><tr><th>شناسه</th><th>نام</th><th>نوع</th><th>مقدار</th><th>یادداشت</th><th>عملیات</th></tr>{trs or "<tr><td colspan=6>موردی نیست</td></tr>"}</table>'
        return self.page(title,body,sess['role'])

    def reports_page(self,sess):
        db=Database(sess['db_path']); inc=db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='income'").fetchone()['x']; exp=db.conn.execute("SELECT COALESCE(SUM(amount),0) x FROM transactions WHERE tx_type='expense'").fetchone()['x']; inv=db.conn.execute("SELECT COUNT(*) x FROM invoices").fetchone()['x']; parties=db.conn.execute("SELECT COUNT(*) x FROM parties").fetchone()['x']; db.close()
        body=f'<div class="grid"><div class="card">درآمد<br><b>{money(inc)}</b></div><div class="card">هزینه<br><b>{money(exp)}</b></div><div class="card">مانده<br><b>{money(int(inc)-int(exp))}</b></div><div class="card">فاکتورها<br><b>{fa_digits(inv)}</b></div></div><p>تعداد طرف حساب‌ها: {fa_digits(parties)}</p>'
        return self.page('گزارش‌ها',body,sess['role'])

    def birthdays_page(self,sess):
        db=Database(sess['db_path']); rows=db.conn.execute("SELECT name,phone,birth_date FROM parties WHERE birth_date IS NOT NULL AND birth_date != ''").fetchall(); db.close(); jp = QCalendar(QCalendar.System.Jalali).partsFromDate(QDate.currentDate()); today_md=(jp.month,jp.day); items=[]
        for r in rows:
            try:
                if jalali_month_day_from_iso(r['birth_date'])==today_md: items.append(f'<li>{r["name"]} - {r["phone"] or "بدون شماره"}</li>')
            except ValueError: pass
        body=f'<ul>{"".join(items) or "<li>امروز تولدی ثبت نشده است.</li>"}</ul><p class="muted">ارسال خودکار فقط وقتی فعال می‌شود که API پیامک در تنظیمات وارد شده باشد.</p>'
        return self.page('🎂 تولدهای امروز',body,sess['role'])

    def settings_page(self,sess):
        db=Database(sess['db_path']); r=db.conn.execute('SELECT * FROM settings WHERE id=1').fetchone(); db.close()
        if sess['role'] == 'maison':
            body=f'<form method="post" action="/settings"><input name="business_name" value="{r["business_name"] or ""}" placeholder="نام مزون"><input name="currency" value="{r["currency"] or "تومان"}" placeholder="واحد پول"><input name="instagram" value="{r["instagram"] or ""}" placeholder="پیج اینستاگرام"><input name="discount" value="{r["birthday_discount"] or 20}" placeholder="درصد تخفیف تولد"><label><input style="width:auto" type="checkbox" name="sms_enabled" value="1" {"checked" if r["sms_enabled"] else ""}> فعال‌سازی بررسی/ارسال پیامک تولد</label><input name="api_url" value="{r["sms_api_url"] or ""}" placeholder="آدرس API پیامک"><input name="api_key" value="{r["sms_api_key"] or ""}" placeholder="کلید API"><input name="sender" value="{r["sms_sender"] or ""}" placeholder="فرستنده SMS"><button>ذخیره</button></form>'
        else:
            body=f'<form method="post" action="/settings"><input name="business_name" value="{r["business_name"] or ""}" placeholder="نام حساب شخصی"><input name="currency" value="{r["currency"] or "تومان"}" placeholder="واحد پول"><button>ذخیره</button></form>'
        current_name = html.escape(username_for_role(sess['role']), quote=True)
        body += f'''<hr><h2>تغییر نام کاربری و رمز عبور این حساب</h2>
        <form method="post" action="/change_credentials">
        <input name="current_password" type="password" placeholder="رمز عبور فعلی" required>
        <input name="new_username" value="{current_name}" placeholder="نام کاربری جدید" required minlength="3">
        <input name="new_password" type="password" placeholder="رمز عبور جدید (حداقل ۶ نویسه)" required minlength="6">
        <input name="repeat_password" type="password" placeholder="تکرار رمز عبور جدید" required minlength="6">
        <button>تغییر اطلاعات ورود</button></form>'''
        return self.page('تنظیمات',body,sess['role'])

    def error_page(self,message):
        return f'<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>{self.css()}</style><body><main><h1>خطا</h1><p>{message}</p><a href="/dashboard">بازگشت</a></main></body></html>'

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Hesabdari Mezon")
    app.setStyle("Fusion")
    app.setStyleSheet("""
        QWidget { font-family: "Segoe UI", "Tahoma"; font-size: 11pt; color: white; }
        QMainWindow, QWidget { background: transparent; color: white; }
        #mainCentral { background-image: url("background_hesabdari.png"); background-repeat: no-repeat; background-position: center; background-attachment: fixed; }
        #header { background: rgba(7,27,58,235); border-radius: 10px; }
        #headerTitle { color: white; font-size: 22pt; font-weight: bold; }
        #card { background: rgba(7,27,58,225); border: 1px solid #35547c; border-radius: 14px; padding: 12px; }
        #cardTitle { color: white; }
        #cardValue { color: white; font-size: 18pt; font-weight: bold; }
        #loginTitle { color: white; font-size: 24pt; font-weight: bold; text-align: center; }
        #errorLabel { color: #ff8a8a; }
        QLabel, QCheckBox, QRadioButton, QGroupBox { color: white; }
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit {
            background: rgba(7,27,58,220); color: white; border: 1px solid #52739e;
            border-radius: 7px; padding: 7px;
        }
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus, QDateEdit:focus { border: 1px solid #d4af37; }
        QPushButton { background: #0b2b55; color: white; border: 1px solid #52739e; border-radius: 8px; padding: 9px 16px; }
        QPushButton:hover { background: #123c73; }
        QTabBar::tab { padding: 11px 18px; color: white; background: rgba(7,27,58,220); }
        QTabBar::tab:selected { background: #d4af37; color: white; border-radius: 7px; }
        QGroupBox { font-weight: bold; margin-top: 10px; }
        QTableWidget, QListWidget, QTreeWidget { background: rgba(7,27,58,225); color: white; alternate-background-color: rgba(18,48,82,225); gridline-color: #35547c; border: 1px solid #35547c; }
        QTableWidget::item:selected, QListWidget::item:selected, QTreeWidget::item:selected { background: #35547c; color: white; }
        QHeaderView::section { background: #0b2b55; color: white; padding: 7px; border: 0; }
        QScrollBar { background: #071b3a; }
    """)
    login = LoginDialog()
    if login.exec() != QDialog.DialogCode.Accepted:
        return 0
    win = AccountingWindow(login.role)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
