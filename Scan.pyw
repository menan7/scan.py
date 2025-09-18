import subprocess
import sys
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
try:
    import tkinter as tk
    from tkinter import ttk, Toplevel, Listbox, Scrollbar, messagebox, Canvas
except ImportError:
    pass # Standard, assume present
try:
    import sqlite3
except ImportError:
    pass # Standard
try:
    import threading
except ImportError:
    pass # Standard
try:
    import time
except ImportError:
    pass # Standard
try:
    import hashlib
except ImportError:
    pass # Standard
# New: Attempt to import coincurve for faster libsecp256k1 bindings
try:
    import coincurve
except ImportError:
    install_package("coincurve")
    try:
        import coincurve
    except ImportError:
        raise ImportError("Failed to install or import coincurve. libsecp256k1 is required.")
try:
    import urllib.request
except ImportError:
    pass # Standard
try:
    import logging
    from logging.handlers import RotatingFileHandler
except ImportError:
    pass # Standard
try:
    import csv
except ImportError:
    pass # Standard
try:
    import os
except ImportError:
    pass # Standard
try:
    import requests
except ImportError:
    install_package("requests")
    import requests
try:
    from datetime import datetime, timedelta
except ImportError:
    pass # Standard
try:
    from multiprocessing import cpu_count
except ImportError:
    pass # Standard
try:
    from decimal import Decimal
except ImportError:
    pass # Standard
try:
    import base58
except ImportError:
    install_package("python-base58")
    import base58
try:
    import pystray
except ImportError:
    install_package("pystray")
    import pystray
try:
    from PIL import Image, ImageDraw
except ImportError:
    install_package("pillow")
    from PIL import Image, ImageDraw
try:
    import asyncio
except ImportError:
    pass # Standard
try:
    from cryptography.fernet import Fernet
except ImportError:
    install_package("cryptography")
    from cryptography.fernet import Fernet
try:
    from telegram.ext import ApplicationBuilder, CommandHandler, CallbackContext, MessageHandler, filters, ConversationHandler
    from telegram import Update
    from telegram.error import NetworkError
except ImportError:
    install_package("python-telegram-bot")
    from telegram.ext import ApplicationBuilder, CommandHandler, CallbackContext, MessageHandler, filters, ConversationHandler
    from telegram import Update
    from telegram.error import NetworkError
import tempfile
import shutil
VERSION = "3.3" # Updated version
# Windows-specific shutdown handler
if sys.platform.startswith('win'):
    try:
        import win32api
    except ImportError:
        install_package("pywin32")
        import win32api
    def win_handler(ctrl_type):
        shutdown_handler()
        return True
    win32api.SetConsoleCtrlHandler(win_handler, True)
# New: For shutdown detection (Feature 02)
import atexit
import signal
import json
from collections import deque
# Setup logging with rotating file handler
import os.path
import platform
script_dir = os.path.dirname(os.path.abspath(__file__))
sys_platform = platform.system()
if sys_platform == 'Windows':
    secure_dir = os.path.join(os.environ.get('APPDATA'), 'HexPuzzleScanner')
elif sys_platform == 'Linux':
    secure_dir = os.path.join(os.path.expanduser('~'), '.hexpuzzlerscanner')
elif sys_platform == 'Darwin':
    secure_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'HexPuzzleScanner')
else:
    secure_dir = os.path.join(script_dir, 'secure') # fallback
os.makedirs(secure_dir, exist_ok=True)
log_dir = os.path.join(secure_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'hex_puzzle_scanner.log')
unsent_file = os.path.join(log_dir, 'unsent_messages.txt')
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
stream_handler = logging.StreamHandler()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[file_handler, stream_handler])
logger = logging.getLogger(__name__)
try:
    COMPUTER_USERNAME = os.getlogin()
except Exception as e:
    COMPUTER_USERNAME = "Unknown"
    logger.warning(f"Failed to get computer username: {e}")
def load_key():
    key_path = os.path.join(secure_dir, "key.bin")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass # Permissions may not work on all OS/filesystems
    return key
token_path = os.path.join(secure_dir, "token.enc")
if not os.path.exists(token_path):
    default_token = "8372815644:AAF0oWoi_BFkFFKrJe-MtaR0v91Kg04RmfY"
    fernet = Fernet(load_key())
    encrypted = fernet.encrypt(default_token.encode())
    with open(token_path, "wb") as f:
        f.write(encrypted)
with open(token_path, "rb") as f:
    encrypted_token = f.read()
fernet = Fernet(load_key())
TELEGRAM_TOKEN = fernet.decrypt(encrypted_token).decode()
chat_id_path = os.path.join(secure_dir, "chat_id.enc")
if not os.path.exists(chat_id_path):
    default_chat_id = "7754070674"
    fernet = Fernet(load_key())
    encrypted = fernet.encrypt(default_chat_id.encode())
    with open(chat_id_path, "wb") as f:
        f.write(encrypted)
with open(chat_id_path, "rb") as f:
    encrypted_chat_id = f.read()
fernet = Fernet(load_key())
CHAT_ID = fernet.decrypt(encrypted_chat_id).decode()
# Update URLs - securely encrypted
update_version_url_path = os.path.join(secure_dir, "update_version_url.enc")
if not os.path.exists(update_version_url_path):
    default_version_url = "https://www.dropbox.com/scl/fi/ayyas9qao9iceoo44s8qw/Version.txt?rlkey=8fkethvld6t6nvg45fg9chlns&st=hixxke9x&dl=1"
    fernet = Fernet(load_key())
    encrypted = fernet.encrypt(default_version_url.encode())
    with open(update_version_url_path, "wb") as f:
        f.write(encrypted)
with open(update_version_url_path, "rb") as f:
    encrypted_version_url = f.read()
fernet = Fernet(load_key())
UPDATE_VERSION_URL = fernet.decrypt(encrypted_version_url).decode()
update_script_url_path = os.path.join(secure_dir, "update_script_url.enc")
if not os.path.exists(update_script_url_path):
    default_script_url = "https://www.dropbox.com/scl/fi/iagx9f4fiwnd4j4an4vv9/scan.pyw?rlkey=hrc8rvjzjcg3zdrejzbpb69md&st=823csnrv&dl=1"
    fernet = Fernet(load_key())
    encrypted = fernet.encrypt(default_script_url.encode())
    with open(update_script_url_path, "wb") as f:
        f.write(encrypted)
with open(update_script_url_path, "rb") as f:
    encrypted_script_url = f.read()
fernet = Fernet(load_key())
UPDATE_SCRIPT_URL = fernet.decrypt(encrypted_script_url).decode()
  
def has_internet():
    try:
        requests.get("https://api.telegram.org", timeout=5)
        return True
    except:
        return False
def send_telegram_message(message):
    retries = 3
    success = False
    for attempt in range(retries):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            payload = {
                "chat_id": CHAT_ID,
                "text": message,
                "parse_mode": "Markdown"
            }
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Sent Telegram message")
            success = True
            break
        except requests.RequestException as e:
            logger.error(f"Attempt {attempt+1}/{retries} failed to send Telegram message: {e}")
            if attempt < retries - 1:
                time.sleep(10)
    if not success:
        with open(unsent_file, 'a', encoding='utf-8') as f:
            f.write(message + '\n')
        logger.info("Queued unsent message")
def message_sender_loop():
    while True:
        time.sleep(60)
        if os.path.exists(unsent_file) and has_internet():
            with open(unsent_file, 'r', encoding='utf-8') as f:
                messages = f.readlines()
            remaining = []
            for msg in messages:
                msg = msg.strip()
                if msg:
                    try:
                        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
                        payload = {
                            "chat_id": CHAT_ID,
                            "text": msg,
                            "parse_mode": "Markdown"
                        }
                        response = requests.post(url, json=payload, timeout=10)
                        response.raise_for_status()
                        logger.info("Sent queued Telegram message")
                    except:
                        remaining.append(msg + '\n')
            with open(unsent_file, 'w', encoding='utf-8') as f:
                f.writelines(remaining)
def parse_version_txt(content):
    lines = content.strip().split('\n')
    version_str = next((line.split('=')[1] for line in lines if line.startswith('VERSION=')), None)
    hash_str = next((line.split('=')[1] for line in lines if line.startswith('HASH=')), None)
    return float(version_str) if version_str else 0.0, hash_str
def check_and_update(silent=False):
    try:
        if not has_internet():
            if not silent:
                send_telegram_message("No internet for update check.")
            return False
        resp = requests.get(UPDATE_VERSION_URL, timeout=10)
        resp.raise_for_status()
        remote_version, remote_hash = parse_version_txt(resp.text)
        local_version = float(VERSION)
        if remote_version <= local_version:
            if not silent:
                send_telegram_message("Up to date.")
            return False
        # Download script
        resp_script = requests.get(UPDATE_SCRIPT_URL, timeout=30)
        resp_script.raise_for_status()
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.py') as temp:
            temp.write(resp_script.content)
            temp_path = temp.name
        # Verify hash
        with open(temp_path, 'rb') as f:
            computed_hash = hashlib.sha256(f.read()).hexdigest()
        if computed_hash != remote_hash:
            os.unlink(temp_path)
            if not silent:
                send_telegram_message("Hash mismatch - corrupt download. Aborted.")
            logger.error("Update hash mismatch")
            return False
        # Replace and restart
        shutil.copy2(temp_path, __file__)
        os.unlink(temp_path)
        msg = f"Successfully updated to version {remote_version}. Restarting..."
        send_telegram_message(msg)
        logger.info(f"Updated to {remote_version} and restarting")
        os.execv(sys.executable, [sys.executable] + sys.argv)
        return True # Unreachable due to execv
    except Exception as e:
        logger.error(f"Update failed: {e}")
        if not silent:
            send_telegram_message("Update check failed. Check logs.")
        return False
def update_poller():
    while True:
        interval_hours = int(get_setting('update_interval_hours', 24))
        time.sleep(interval_hours * 3600)
        check_and_update(silent=True)
num_cores = cpu_count()
if num_cores > 8:
    default_threads = 4
elif num_cores > 6:
    default_threads = 3
else:
    default_threads = min(4, num_cores)
batch_size = 512 if num_cores <= 2 else 1024
CONFIG = {
    'chunk_size': 2000,
    'merge_interval': 100,
    'gui_update_ms': 5000,
    'balance_check_retries': 3,
    'balance_check_delay': 2,
    'details_font': ("Arial", 10),
    'details_bold_font': ("Arial", 10, "bold"),
    'details_width': 80,
    'telegram_update_interval': 10800,
    'visualizer_height': 30,
    'default_num_threads': default_threads,
    'batch_size': batch_size, # Adjusted based on cores
    'details_update_interval': 30000, # New: Update details every 30s to reduce DB load
}
PUZZLES = [
    (70, '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR', '0000000000000000000000000000000000000000000000200000000000000000', '00000000000000000000000000000000000000000000003fffffffffffffffff'),
    (71, '1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU', '0000000000000000000000000000000000000000000000400000000000000000', '00000000000000000000000000000000000000000000007fffffffffffffffff'),
    (72, '1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR', '0000000000000000000000000000000000000000000000800000000000000000', '0000000000000000000000000000000000000000000000ffffffffffffffffff'),
    (73, '12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4', '0000000000000000000000000000000000000000000001000000000000000000', '0000000000000000000000000000000000000000000001ffffffffffffffffff'),
    (74, '1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv', '0000000000000000000000000000000000000000000002000000000000000000', '0000000000000000000000000000000000000000000003ffffffffffffffffff')
]
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def compute_address_bytes(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    extended_rip = b'\x00' + rip
    checksum = hashlib.sha256(hashlib.sha256(extended_rip).digest()).digest()[:4]
    return extended_rip + checksum
# Unused now, but kept for reference
def private_key_to_address(privkey_int):
    privkey_bytes = privkey_int.to_bytes(32, 'big')
    pubkey = coincurve.PublicKey.from_secret(privkey_bytes)
    pubkey_bytes = pubkey.format(compressed=True)
    address_bytes = compute_address_bytes(pubkey_bytes)
    return base58.b58encode(address_bytes).decode('utf-8')
def private_key_to_uncompressed_address(privkey_int):
    privkey_bytes = privkey_int.to_bytes(32, 'big')
    pubkey = coincurve.PublicKey.from_secret(privkey_bytes)
    pubkey_bytes = pubkey.format(compressed=False)
    sha = hashlib.sha256(pubkey_bytes).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    extended_rip = b'\x00' + rip
    checksum = hashlib.sha256(hashlib.sha256(extended_rip).digest()).digest()[:4]
    address_bytes = extended_rip + checksum
    return base58.b58encode(address_bytes).decode('utf-8')
def priv_to_wif(priv_hex):
    priv_bytes = bytes.fromhex(priv_hex)
    extended = b'\x80' + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')
def get_balance(address):
    for _ in range(CONFIG['balance_check_retries']):
        try:
            url = f"https://blockchain.info/q/addressbalance/{address}"
            with urllib.request.urlopen(url, timeout=10) as response:
                satoshi = int(response.read())
                return satoshi / 100000000.0
        except Exception as e:
            logger.warning(f"Balance check failed for {address}: {e}")
            time.sleep(CONFIG['balance_check_delay'])
    logger.error(f"Failed to get balance for {address} after {CONFIG['balance_check_retries']} retries")
    return 0.0
def merge_intervals(intervals):
    if not intervals:
        return []
    sorted_intervals = sorted(intervals, key=lambda x: x[0])
    merged = [list(sorted_intervals[0])]
    for current in sorted_intervals[1:]:
        last = merged[-1]
        if current[0] <= last[1] + 1:
            last[1] = max(last[1], current[1])
        else:
            merged.append(list(current))
    return merged
def subtract_intervals(target_start, target_end, to_subtract):
    remaining = [(target_start, target_end, None)]
    for sub in to_subtract:
        new_remaining = []
        for rem_start, rem_end, rem_timestamp in remaining:
            if rem_end < sub[0] or rem_start > sub[1]:
                new_remaining.append((rem_start, rem_end, rem_timestamp))
            else:
                if rem_start < sub[0]:
                    new_remaining.append((rem_start, sub[0] - 1, rem_timestamp))
                if rem_end > sub[1]:
                    new_remaining.append((sub[1] + 1, rem_end, rem_timestamp))
        remaining = new_remaining
    return remaining
DB_FILE = os.path.join(script_dir, "puzzle.db")
FOUND_FILE = os.path.join(secure_dir, "found.enc")
DB_LOCK = threading.Lock()
def init_db():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute('''CREATE TABLE IF NOT EXISTS puzzles (
                puzzle_no INTEGER PRIMARY KEY,
                address TEXT,
                start_key TEXT,
                stop_key TEXT
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS scanned_ranges (
                puzzle_no INTEGER,
                start_key TEXT,
                stop_key TEXT,
                timestamp TEXT
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS skip_ranges (
                puzzle_no INTEGER,
                start_key TEXT,
                stop_key TEXT,
                timestamp TEXT
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS active_progress (
                puzzle_no INTEGER,
                thread_id INTEGER,
                sub_index INTEGER,
                current_key TEXT,
                mode TEXT,
                target_start TEXT,
                target_end TEXT,
                direction TEXT,
                part_index INTEGER DEFAULT 0,
                num_parts INTEGER DEFAULT 0,
                session_start_key TEXT,
                session_last_key TEXT,
                PRIMARY KEY (puzzle_no, thread_id)
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS recent_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                puzzle_no INTEGER,
                mode TEXT,
                target_start TEXT,
                target_end TEXT,
                direction TEXT,
                completed INTEGER DEFAULT 0,
                timestamp TEXT,
                part_index INTEGER DEFAULT 0,
                num_parts INTEGER DEFAULT 0
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')
            cur.execute("PRAGMA table_info(active_progress)")
            columns = [col[1] for col in cur.fetchall()]
            if 'thread_id' not in columns:
                cur.execute("ALTER TABLE active_progress ADD COLUMN thread_id INTEGER")
                logger.info("Added thread_id column to active_progress table")
            for p in PUZZLES:
                cur.execute("INSERT OR IGNORE INTO puzzles VALUES (?, ?, ?, ?)", p)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scanned_puzzle_timestamp ON scanned_ranges (puzzle_no, timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_skip_puzzle_timestamp ON skip_ranges (puzzle_no, timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_active_puzzle_thread ON active_progress (puzzle_no, thread_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_recent_puzzle_timestamp ON recent_scans (puzzle_no, timestamp)")
            conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
    finally:
        conn.close()
def vacuum_db():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("VACUUM")
            cur.execute("PRAGMA optimize")
            conn.commit()
            logger.info("Database vacuumed and optimized for better performance")
    except sqlite3.Error as e:
        logger.error(f"Failed to vacuum/optimize database: {e}")
    finally:
        conn.close()
def get_setting(key, default=None):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else default
    except sqlite3.Error as e:
        logger.error(f"Failed to get setting {key}: {e}")
        return default
def set_setting(key, value):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        logger.error(f"Failed to set setting {key}: {e}")
def get_puzzle_details(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT * FROM puzzles WHERE puzzle_no = ?", (puzzle_no,))
        row = cur.fetchone()
        conn.close()
        if row:
            logger.info(f"Retrieved puzzle details for puzzle {puzzle_no}")
            return {'puzzle_no': row[0], 'address': row[1], 'start_key': row[2], 'stop_key': row[3]}
        logger.warning(f"No puzzle details found for puzzle {puzzle_no}")
        return None
    except sqlite3.Error as e:
        logger.error(f"Failed to get puzzle details for {puzzle_no}: {e}")
        return None
def get_scanned_ranges(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT start_key, stop_key, timestamp FROM scanned_ranges WHERE puzzle_no = ?", (puzzle_no,))
        ranges = []
        for start, stop, timestamp in cur.fetchall():
            try:
                ranges.append((int(start, 16), int(stop, 16), timestamp))
            except ValueError as e:
                logger.error(f"Invalid hex in scanned_ranges for puzzle {puzzle_no}: start={start}, stop={stop}, error={e}")
        conn.close()
        merged_ranges = merge_intervals([(r[0], r[1]) for r in ranges])
        merged_with_timestamp = []
        for start, end in merged_ranges:
            latest_timestamp = None
            for r_start, r_end, ts in ranges:
                if r_start <= end and r_end >= start:
                    if latest_timestamp is None or (ts and (not latest_timestamp or ts > latest_timestamp)):
                        latest_timestamp = ts
            merged_with_timestamp.append((start, end, latest_timestamp))
        logger.info(f"Retrieved {len(merged_with_timestamp)} scanned ranges for puzzle {puzzle_no}")
        return merged_with_timestamp
    except sqlite3.Error as e:
        logger.error(f"Failed to get scanned ranges for {puzzle_no}: {e}")
        return []
def get_scanned_ranges_with_timestamp(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT start_key, stop_key, timestamp FROM scanned_ranges WHERE puzzle_no = ? ORDER BY timestamp DESC", (puzzle_no,))
        ranges = []
        for start, stop, timestamp in cur.fetchall():
            try:
                ranges.append((start, stop, timestamp))
            except ValueError as e:
                logger.error(f"Invalid hex in scanned_ranges for puzzle {puzzle_no}: start={start}, stop={stop}, error={e}")
        conn.close()
        logger.info(f"Retrieved {len(ranges)} scanned ranges with timestamps for puzzle {puzzle_no}")
        return ranges
    except sqlite3.Error as e:
        logger.error(f"Failed to get scanned ranges with timestamps for {puzzle_no}: {e}")
        return []
def get_skip_ranges(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT start_key, stop_key, timestamp FROM skip_ranges WHERE puzzle_no = ?", (puzzle_no,))
        ranges = []
        for start, stop, timestamp in cur.fetchall():
            try:
                if not (len(start) == 64 and len(stop) == 64 and all(c in '0123456789abcdefABCDEF' for c in start + stop)):
                    logger.warning(f"Invalid hex format in skip_ranges for puzzle {puzzle_no}: start={start}, stop={stop}")
                    continue
                ranges.append((int(start, 16), int(stop, 16), timestamp))
            except ValueError as e:
                logger.error(f"Invalid hex in skip_ranges for puzzle {puzzle_no}: start={start}, stop={stop}, error={e}")
        conn.close()
        logger.info(f"Retrieved {len(ranges)} skip ranges for puzzle {puzzle_no}")
        return ranges
    except sqlite3.Error as e:
        logger.error(f"Failed to get skip ranges for {puzzle_no}: {e}")
        return []
def get_last_scanned_key(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT stop_key FROM scanned_ranges WHERE puzzle_no = ? ORDER BY timestamp DESC LIMIT 1", (puzzle_no,))
        row = cur.fetchone()
        conn.close()
        if row:
            logger.info(f"Retrieved last scanned key for puzzle {puzzle_no}: {row[0]}")
            return row[0]
        return None
    except sqlite3.Error as e:
        logger.error(f"Failed to get last scanned key for {puzzle_no}: {e}")
        return None
def get_last_scanned_timestamp(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT timestamp FROM scanned_ranges WHERE puzzle_no = ? ORDER BY timestamp DESC LIMIT 1", (puzzle_no,))
        row = cur.fetchone()
        conn.close()
        if row:
            logger.info(f"Retrieved last scanned timestamp for puzzle {puzzle_no}: {row[0]}")
            return row[0]
        return None
    except sqlite3.Error as e:
        logger.error(f"Failed to get last scanned timestamp for {puzzle_no}: {e}")
        return None
def add_scanned_range(puzzle_no, start_hex, stop_hex):
    try:
        local_time = datetime.now().strftime('%H:%M:%S, %d/%m/%Y')
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("INSERT INTO scanned_ranges (puzzle_no, start_key, stop_key, timestamp) VALUES (?, ?, ?, ?)",
                        (puzzle_no, start_hex, stop_hex, local_time))
            conn.commit()
            logger.info(f"Added scanned range for puzzle {puzzle_no}: {start_hex} to {stop_hex}, timestamp={local_time}")
    except sqlite3.Error as e:
        logger.error(f"Failed to add scanned range for {puzzle_no}: {e}")
    finally:
        conn.close()
def merge_scanned_ranges(puzzle_no):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT start_key, stop_key, timestamp FROM scanned_ranges WHERE puzzle_no = ?", (puzzle_no,))
            ranges = []
            for start, stop, ts in cur.fetchall():
                try:
                    ranges.append((int(start, 16), int(stop, 16), ts))
                except ValueError:
                    continue
            if not ranges:
                return
            sorted_ranges = sorted(ranges, key=lambda x: x[0])
            merged = [list(sorted_ranges[0])]
            for current in sorted_ranges[1:]:
                last = merged[-1]
                if current[0] <= last[1] + 1:
                    last[1] = max(last[1], current[1])
                    if current[2] > last[2]:
                        last[2] = current[2]
                else:
                    merged.append(list(current))
            cur.execute("DELETE FROM scanned_ranges WHERE puzzle_no = ?", (puzzle_no,))
            for start, end, ts in merged:
                cur.execute("INSERT INTO scanned_ranges (puzzle_no, start_key, stop_key, timestamp) VALUES (?, ?, ?, ?)",
                            (puzzle_no, hex(start)[2:].zfill(64), hex(end)[2:].zfill(64), ts))
            conn.commit()
            logger.info(f"Merged {len(ranges)} scanned ranges into {len(merged)} for puzzle {puzzle_no}")
    except sqlite3.Error as e:
        logger.error(f"Failed to merge scanned ranges for {puzzle_no}: {e}")
    finally:
        conn.close()
def add_skip_range(puzzle_no, start_hex, end_hex):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT start_key, stop_key FROM skip_ranges WHERE puzzle_no = ? AND start_key = ? AND stop_key = ?",
                        (puzzle_no, start_hex, end_hex))
            if cur.fetchone():
                raise ValueError(f"Skip range {start_hex} to {end_hex} already exists for puzzle {puzzle_no}")
            local_time = datetime.now().strftime('%H:%M:%S, %d/%m/%Y')
            cur.execute("INSERT INTO skip_ranges (puzzle_no, start_key, stop_key, timestamp) VALUES (?, ?, ?, ?)",
                        (puzzle_no, start_hex, end_hex, local_time))
            conn.commit()
            cur.execute("SELECT start_key, stop_key, timestamp FROM skip_ranges WHERE puzzle_no = ? AND start_key = ? AND stop_key = ?",
                        (puzzle_no, start_hex, end_hex))
            row = cur.fetchone()
            if not row:
                raise sqlite3.Error("Failed to verify inserted skip range")
            logger.info(f"Added and verified skip range for puzzle {puzzle_no}: {start_hex} to {end_hex}, timestamp={local_time}")
            return True
    except (sqlite3.Error, ValueError) as e:
        logger.error(f"Failed to add skip range for {puzzle_no}: {e}")
        raise
    finally:
        conn.close()
def get_active_progress(puzzle_no, thread_id=None):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        if thread_id is not None:
            cur.execute("SELECT * FROM active_progress WHERE puzzle_no = ? AND thread_id = ?", (puzzle_no, thread_id))
            row = cur.fetchone()
            conn.close()
            if row:
                logger.info(f"Retrieved active progress for puzzle {puzzle_no}, thread {thread_id}")
                return {
                    'thread_id': row[1],
                    'sub_index': row[2],
                    'current_key': row[3],
                    'mode': row[4],
                    'target_start': row[5],
                    'target_end': row[6],
                    'direction': row[7],
                    'part_index': row[8],
                    'num_parts': row[9],
                    'session_start_key': row[10],
                    'session_last_key': row[11]
                }
            return None
        else:
            cur.execute("SELECT * FROM active_progress WHERE puzzle_no = ?", (puzzle_no,))
            rows = cur.fetchall()
            conn.close()
            progress = []
            for row in rows:
                progress.append({
                    'thread_id': row[1],
                    'sub_index': row[2],
                    'current_key': row[3],
                    'mode': row[4],
                    'target_start': row[5],
                    'target_end': row[6],
                    'direction': row[7],
                    'part_index': row[8],
                    'num_parts': row[9],
                    'session_start_key': row[10],
                    'session_last_key': row[11]
                })
            logger.info(f"Retrieved {len(progress)} active progress entries for puzzle {puzzle_no}")
            return progress
    except sqlite3.Error as e:
        logger.error(f"Failed to get active progress for {puzzle_no}: {e}")
        return []
def save_active_progress(puzzle_no, thread_id, sub_index, current_key, mode, target_start, target_end, direction, part_index=0, num_parts=0, session_start_key=None, session_last_key=None):
    try:
        if not (isinstance(current_key, str) and len(current_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in current_key)):
            logger.error(f"Invalid current_key for puzzle {puzzle_no}, thread {thread_id}: {current_key}")
            return
        num_parts = int(num_parts)
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("REPLACE INTO active_progress VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (puzzle_no, thread_id, sub_index, current_key, mode, target_start, target_end, direction, part_index, num_parts, session_start_key, session_last_key))
            conn.commit()
            logger.info(f"Saved active progress for puzzle {puzzle_no}, thread {thread_id}: key={current_key}, session_start_key={session_start_key}, session_last_key={session_last_key}")
    except (sqlite3.Error, ValueError) as e:
        logger.error(f"Failed to save active progress for {puzzle_no}, thread {thread_id}: {e}")
    finally:
        conn.close()
def clear_active_progress(puzzle_no):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("DELETE FROM active_progress WHERE puzzle_no = ?", (puzzle_no,))
            conn.commit()
            logger.info(f"Cleared active progress for puzzle {puzzle_no}")
    except sqlite3.Error as e:
        logger.error(f"Failed to clear active progress for {puzzle_no}: {e}")
    finally:
        conn.close()
def clean_active_progress():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("DELETE FROM active_progress WHERE LENGTH(current_key) != 64 OR current_key GLOB '*[^0-9a-fA-F]*' OR num_parts GLOB '*[^0-9]*'")
            conn.commit()
            logger.info("Cleaned invalid entries from active_progress table")
    except sqlite3.Error as e:
        logger.error(f"Failed to clean active_progress table: {e}")
    finally:
        conn.close()
def add_recent_scan(puzzle_no, mode, target_start, target_end, direction, completed, part_index=0, num_parts=0):
    try:
        local_time = datetime.now().strftime('%H:%M:%S, %d/%m/%Y')
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("INSERT INTO recent_scans (puzzle_no, mode, target_start, target_end, direction, completed, timestamp, part_index, num_parts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (puzzle_no, mode, target_start, target_end, direction, completed, local_time, part_index, num_parts))
            conn.commit()
            logger.info(f"Added recent scan for puzzle {puzzle_no}: mode={mode}, completed={completed}")
    except sqlite3.Error as e:
        logger.error(f"Failed to add recent scan for {puzzle_no}: {e}")
    finally:
        conn.close()
def get_recent_scans(puzzle_no):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT id, mode, target_start, target_end, direction, completed, timestamp, part_index, num_parts FROM recent_scans WHERE puzzle_no = ? ORDER BY timestamp DESC", (puzzle_no,))
        rows = cur.fetchall()
        conn.close()
        recent = []
        for row in rows:
            recent.append({
                'id': row[0],
                'mode': row[1],
                'target_start': row[2],
                'target_end': row[3],
                'direction': row[4],
                'completed': row[5],
                'timestamp': row[6],
                'part_index': row[7],
                'num_parts': row[8]
            })
        logger.info(f"Retrieved {len(recent)} recent scans for puzzle {puzzle_no}")
        return recent
    except sqlite3.Error as e:
        logger.error(f"Failed to get recent scans for {puzzle_no}: {e}")
        return []
def update_recent_scan_completed(scan_id, completed):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("UPDATE recent_scans SET completed = ? WHERE id = ?", (completed, scan_id))
            conn.commit()
            logger.info(f"Updated recent scan id {scan_id} completed to {completed}")
    except sqlite3.Error as e:
        logger.error(f"Failed to update recent scan id {scan_id}: {e}")
    finally:
        conn.close()
def format_key(key):
    if key is None or key == 'None':
        return 'None'
    return key.lstrip('0') or '0'
class ScanThread(threading.Thread):
    def __init__(self, gui, puzzle_no, target_start_int, target_end_int, direction, mode, address, parts=None, part_index=0, thread_id=0, is_new_scan=True, allow_rescan=False, scan_id=None, scan_type="sequential"):
        super().__init__()
        self.gui = gui
        self.puzzle_no = puzzle_no
        self.target_start_int = target_start_int
        self.target_end_int = target_end_int
        self.direction = direction
        self.mode = mode
        self.address = address
        self.target_address_bytes = base58.b58decode(address) # Predecode target for byte comparison
        self.parts = parts if mode == 'part' else None
        self.current_part_index = part_index
        self.thread_id = thread_id
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.scan_type = scan_type
        self.step = 1 if direction == 'forward' else -1
        self.scanned_this_session = 0
        self.speed = 0.0
        self.last_speed_time = time.time()
        self.keys_since_speed = 0
        self.last_save_time = time.time()
        self.chunk_size = CONFIG['chunk_size']
        self.batch_size = CONFIG['batch_size']
        self.chunk_count = 0
        self.current_chunk_start = None
        self.last_chunk_key = None
        self.session_last_key = None
        self.allow_rescan = allow_rescan
        self.scan_id = scan_id
        self.total_range_keys = self.target_end_int - self.target_start_int + 1
        self.last_telegram_update = time.time()
        self._compute_remaining()
        active = get_active_progress(puzzle_no, thread_id)
        if self.scan_type == 'sequential':
            if is_new_scan:
                self.current_sub_index = 0
                self._set_initial_key()
                self.session_start_key = hex(self.current_key)[2:].zfill(64) if self.current_key else None
                self.session_last_key = None
                if self.scan_id is None:
                    add_recent_scan(puzzle_no, mode, hex(self.target_start_int)[2:].zfill(64), hex(self.target_end_int)[2:].zfill(64), direction, 0, part_index, len(self.parts) if self.parts else 0)
                    recent = get_recent_scans(puzzle_no)
                    self.scan_id = recent[0]['id'] if recent else None
                logger.info(f"New scan initialized for puzzle {puzzle_no}, thread {thread_id}, session_start_key: {self.session_start_key}, allow_rescan: {self.allow_rescan}, scan_id: {self.scan_id}")
            else:
                if active and active['mode'] == mode and active['target_start'] == hex(self.target_start_int)[2:].zfill(64) and active['target_end'] == hex(self.target_end_int)[2:].zfill(64):
                    self.current_sub_index = active['sub_index']
                    self.current_part_index = active['part_index']
                    try:
                        self.current_key = int(active['current_key'], 16) if active['current_key'] else None
                    except ValueError:
                        logger.error(f"Invalid current_key in active_progress for puzzle {puzzle_no}, thread {thread_id}: {active['current_key']}")
                        self.current_key = None
                        self._set_initial_key()
                    self.session_start_key = active['session_start_key'] or (hex(self.current_key)[2:].zfill(64) if self.current_key else None)
                    self.session_last_key = active['session_last_key'] or None
                    if self.mode == 'part':
                        self.num_parts = int(active['num_parts'])
                    if not self._is_key_in_current_sub():
                        self._advance_to_next_sub()
                    logger.info(f"Resumed scan for puzzle {puzzle_no}, thread {thread_id}, session_start_key: {self.session_start_key}, session_last_key: {self.session_last_key}, allow_rescan: {self.allow_rescan}")
                else:
                    self.current_sub_index = 0
                    self._set_initial_key()
                    self.session_start_key = hex(self.current_key)[2:].zfill(64) if self.current_key else None
                    self.session_last_key = None
                    logger.info(f"No matching active progress, initialized new session for puzzle {puzzle_no}, thread {thread_id}, session_start_key: {self.session_start_key}, allow_rescan: {self.allow_rescan}")
            self.current_chunk_start = self.current_key
            # Incremental ECC setup
            if self.current_key is not None:
                self.current_pub_bytes = coincurve.PublicKey.from_secret(self.current_key.to_bytes(32, 'big')).format(compressed=True)
            else:
                self.current_pub_bytes = None
    def _compute_remaining(self):
        skips = get_skip_ranges(self.puzzle_no)
        to_subtract = []
        to_subtract = [(s[0], s[1]) for s in skips]
        if not self.allow_rescan:
            scanned = get_scanned_ranges(self.puzzle_no)
            to_subtract.extend([(s[0], s[1]) for s in scanned])
        to_subtract = merge_intervals(to_subtract)
        self.remaining_sub = subtract_intervals(self.target_start_int, self.target_end_int, to_subtract)
        self.total_remaining_keys = sum(end - start + 1 for start, end, _ in self.remaining_sub)
        if self.direction == 'reverse':
            self.remaining_sub.sort(key=lambda x: x[0], reverse=True)
        logger.info(f"Computed remaining subranges for puzzle {self.puzzle_no}, thread {self.thread_id}: {len(self.remaining_sub)} subranges, {self.total_remaining_keys:,} keys total, allow_rescan: {self.allow_rescan}")
    def _set_initial_key(self):
        if self.remaining_sub:
            sub = self.remaining_sub[self.current_sub_index]
            self.current_key = sub[0] if self.step == 1 else sub[1]
            self.current_chunk_start = self.current_key
            self.current_pub_bytes = coincurve.PublicKey.from_secret(self.current_key.to_bytes(32, 'big')).format(compressed=True)
        else:
            self.current_key = None
            self.current_pub_bytes = None
            logger.warning(f"No remaining subranges for puzzle {self.puzzle_no}, thread {self.thread_id}")
    def _is_key_in_current_sub(self):
        if self.current_sub_index >= len(self.remaining_sub):
            return False
        sub = self.remaining_sub[self.current_sub_index]
        return sub[0] <= self.current_key <= sub[1]
    def _advance_to_next_sub(self):
        self.current_sub_index += 1
        if self.current_sub_index < len(self.remaining_sub):
            sub = self.remaining_sub[self.current_sub_index]
            self.current_key = sub[0] if self.step == 1 else sub[1]
            self.current_pub_bytes = coincurve.PublicKey.from_secret(self.current_key.to_bytes(32, 'big')).format(compressed=True)
            self.current_chunk_start = self.current_key
            logger.info(f"Advanced to subrange {self.current_sub_index + 1}/{len(self.remaining_sub)}: {hex(self.current_key)[2:].zfill(64)}, thread {self.thread_id}")
        else:
            if self.mode == 'part' and self.parts and self.current_part_index < len(self.parts) - 1:
                self.current_part_index += 1
                self.target_start_int, self.target_end_int = self.parts[self.current_part_index]
                self.total_range_keys = self.target_end_int - self.target_start_int + 1
                self._compute_remaining()
                self.current_sub_index = 0
                self._set_initial_key()
                self.session_start_key = hex(self.current_key)[2:].zfill(64) if self.current_key else None
                self.session_last_key = None
                logger.info(f"Advanced to part {self.current_part_index + 1}/{len(self.parts)}, thread {self.thread_id}, session_start_key: {self.session_start_key}")
            else:
                self.stop_event.set()
                if self.scan_id:
                    update_recent_scan_completed(self.scan_id, 1)
                logger.info(f"No more subranges or parts for puzzle {self.puzzle_no}, thread {self.thread_id}, stopping scan")
    def _mark_chunk(self):
        if self.last_chunk_key is not None:
            chunk_min = min(self.current_chunk_start, self.last_chunk_key)
            chunk_max = max(self.current_chunk_start, self.last_chunk_key)
            add_scanned_range(self.puzzle_no, hex(chunk_min)[2:].zfill(64), hex(chunk_max)[2:].zfill(64))
            self.chunk_count += 1
            if self.chunk_count >= CONFIG['merge_interval']:
                merge_scanned_ranges(self.puzzle_no)
                self.chunk_count = 0
                self._compute_remaining()
            self.current_chunk_start = self.last_chunk_key + self.step
            logger.debug(f"Marked chunk: {hex(chunk_min)[2:].zfill(64)} to {hex(chunk_max)[2:].zfill(64)}, thread {self.thread_id}")
        self.last_chunk_key = None
    def run(self):
        self.last_chunk_key = None
        self.session_start_key = self.session_start_key
        found = False
        while not self.stop_event.is_set() and self.remaining_sub:
            if self.pause_event.is_set():
                if self.last_chunk_key is not None:
                    self.session_last_key = hex(self.last_chunk_key)[2:].zfill(64)
                elif self.current_key is not None:
                    self.session_last_key = hex(self.current_key)[2:].zfill(64)
                self._mark_chunk()
                if self.session_last_key:
                    save_active_progress(self.puzzle_no, self.thread_id, self.current_sub_index,
                                        hex(self.current_key)[2:].zfill(64) if self.current_key else None, self.mode,
                                        hex(self.target_start_int)[2:].zfill(64),
                                        hex(self.target_end_int)[2:].zfill(64),
                                        self.direction, self.current_part_index,
                                        len(self.parts) if self.parts else 0,
                                        self.session_start_key, self.session_last_key)
                time.sleep(1)
                continue
            # Batch processing: Compute batch_size keys at once
            batch_keys_scanned = 0
            current_key = self.current_key
            current_pub_bytes = self.current_pub_bytes
            # Precompute tweak for G or -G
            tweak = (1 if self.step == 1 else -1).to_bytes(32, 'big')
            for _ in range(self.batch_size):
                if self.stop_event.is_set() or not self._is_key_in_current_sub():
                    break
                address_bytes = compute_address_bytes(current_pub_bytes)
                if address_bytes == self.target_address_bytes:
                    priv_hex = hex(current_key)[2:].zfill(64)
                    wif = priv_to_wif(priv_hex)
                    balance = get_balance(self.address)
                    msg = (
                        f"*User*: {COMPUTER_USERNAME}\n"
                        "🎉 *Found! Puzzle Solved!* 🏆\n"
                        f"*Puzzle*: #{self.puzzle_no}\n"
                        f"*Thread*: {self.thread_id}\n"
                        f"*Address*: `{self.address}`\n"
                        f"*Hex Key*: `{priv_hex}`\n"
                        f"*WIF Key*: `{wif}`\n"
                        f"💰 *Balance*: {balance} BTC\n"
                        f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
                    )
                    try:
                        fernet = Fernet(self.gui.key)
                        encrypted_msg = fernet.encrypt(msg.encode('utf-8'))
                        with open(FOUND_FILE, "ab") as f:
                            f.write(encrypted_msg + b"\n")
                    except Exception as e:
                        logger.error(f"Failed to write encrypted to found.enc: {e}")
                    send_telegram_message(msg)
                    self.gui.stop_all_threads()
                    found = True
                    break
                self.last_chunk_key = current_key
                self.session_last_key = hex(current_key)[2:].zfill(64)
                current_key += self.step
                # Incremental tweak add with libsecp256k1
                current_pub = coincurve.PublicKey(current_pub_bytes)
                current_pub = current_pub.add(tweak) # use add() instead of tweak_add
                current_pub_bytes = current_pub.format(compressed=True)
                batch_keys_scanned += 1
                self.scanned_this_session += 1
                self.keys_since_speed += 1
            self.current_key = current_key
            self.current_pub_bytes = current_pub_bytes
            if found:
                break
            if batch_keys_scanned % self.chunk_size == 0:
                self._mark_chunk()
            if not self._is_key_in_current_sub():
                self._mark_chunk()
                self._advance_to_next_sub()
            current_time = time.time()
            if current_time - self.last_speed_time > 10:
                self.speed = self.keys_since_speed / (current_time - self.last_speed_time)
                self.keys_since_speed = 0
                self.last_speed_time = current_time
                logger.debug(f"Scan speed: {self.speed:.2f} keys/sec, thread {self.thread_id}")
            if CONFIG['telegram_update_interval'] > 0 and current_time - self.last_telegram_update > CONFIG['telegram_update_interval']:
                details = get_puzzle_details(self.puzzle_no)
                puzzle_start = int(details['start_key'], 16)
                puzzle_end = int(details['stop_key'], 16)
                total = puzzle_end - puzzle_start + 1
                current = int(self.session_last_key, 16) if self.session_last_key else puzzle_start
                percent = ((current - puzzle_start) / total) * 100 if total > 0 else 0
                update_message = (
                    f"*User*: {COMPUTER_USERNAME}\n"
                    "📊 *Progress Update* 📊\n"
                    f"*Puzzle*: #{self.puzzle_no}\n"
                    f"*Thread*: {self.thread_id}\n"
                    f"*Mode*: {self.mode.capitalize()}\n"
                    f"*Keys Scanned (This Session)*: `{self.scanned_this_session:,}`\n"
                    f"*Last Key*: `{format_key(self.session_last_key)}`\n"
                    f"*Session Start Key*: `{format_key(self.session_start_key)}`\n"
                    f"*Session Last Key*: `{format_key(self.session_last_key)}`\n"
                    f"⚡ *Speed*: {self.speed:.2f} keys/sec\n"
                    f"*Progress*: {percent:.10f}%\n"
                    f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
                )
                send_telegram_message(update_message)
                self.last_telegram_update = time.time()
            if current_time - self.last_save_time > 60:
                save_active_progress(self.puzzle_no, self.thread_id, self.current_sub_index,
                                    hex(self.current_key)[2:].zfill(64) if self.current_key else '0'*64, self.mode,
                                    hex(self.target_start_int)[2:].zfill(64),
                                    hex(self.target_end_int)[2:].zfill(64),
                                    self.direction, self.current_part_index,
                                    len(self.parts) if self.parts else 0,
                                    self.session_start_key, self.session_last_key)
                self.last_save_time = current_time
                logger.debug(f"Saved progress at key: {hex(self.current_key)[2:].zfill(64) if self.current_key else 'None'}, session_start_key: {self.session_start_key}, thread {self.thread_id}")
        if self.last_chunk_key is not None:
            self.session_last_key = hex(self.last_chunk_key)[2:].zfill(64)
        elif self.current_key is not None:
            self.session_last_key = hex(self.current_key)[2:].zfill(64)
        if self.session_start_key or self.session_last_key:
            save_active_progress(self.puzzle_no, self.thread_id, self.current_sub_index,
                                hex(self.current_key)[2:].zfill(64) if self.current_key else '0'*64,
                                self.mode,
                                hex(self.target_start_int)[2:].zfill(64),
                                hex(self.target_end_int)[2:].zfill(64),
                                self.direction, self.current_part_index,
                                len(self.parts) if self.parts else 0,
                                self.session_start_key, self.session_last_key)
        self._mark_chunk()
        if not self.remaining_sub:
            try:
                with DB_LOCK:
                    conn = sqlite3.connect(DB_FILE)
                    cur = conn.cursor()
                    cur.execute("DELETE FROM active_progress WHERE puzzle_no = ? AND thread_id = ?", (self.puzzle_no, self.thread_id))
                    conn.commit()
                    logger.info(f"Deleted active progress for completed thread {self.thread_id}, puzzle {self.puzzle_no}")
            except sqlite3.Error as e:
                logger.error(f"Failed to delete active progress for {self.puzzle_no}, thread {self.thread_id}: {e}")
            finally:
                conn.close()
        logger.info(f"Scan stopped for puzzle {self.puzzle_no}, thread {self.thread_id}")
class HexPuzzleGUI:
    def __init__(self, root):
        self.root = root
        self.root.withdraw() # Hide immediately to prevent flash
        self.script_start_time = datetime.now()
        self.root.title("Smart solver")
        self.root.minsize(350, 200)
        self.root.resizable(False, False)
        self.center_window(self.root, 350, 220)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.scan_threads = []
        self.puzzle_var = tk.StringVar(value="71")
        self.multithread_var = tk.BooleanVar(value=False)
        self.num_threads_var = tk.IntVar(value=CONFIG['default_num_threads'])
        self.telegram_notifications_var = tk.BooleanVar(value=True)
        self.allow_rescan_var = tk.BooleanVar(value=False)
        self.update_id = None
        self.font = CONFIG['details_font']
        self.bold_font = CONFIG['details_bold_font']
        self.tray_icon = None
        self.telegram_bot_thread = None
        self.telegram_application = None
        self.key = load_key()
        self.load_config()
        self.locked = get_setting('config_locked', '0') == '1'
        self.stop_async_event = asyncio.Event()
        self.bot_loop = None
        self.last_visualizer_update = time.time()
        self.remote_status = None # Will be set in UI
        global remote_mode, pending, bot_state
        remote_mode = True
        pending = None
        bot_state = {}
        self.suspended_scan = None
        # Windows-specific
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', font=self.font)
        style.configure('TButton', font=("Arial", 8), padding=(2, 1))
        style.configure('TCombobox', font=self.font)
        style.configure('TCheckbutton', font=self.font)
        self.main_frame = ttk.Frame(self.root, padding=3)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.progress_frame = ttk.LabelFrame(self.main_frame, text=".......", padding=4)
        self.progress_frame.grid(row=0, column=0, sticky="nsew", pady=5)
        self.status_label = ttk.Label(self.progress_frame, text="Status: Idle")
        self.status_label.grid(row=0, column=0, sticky="w", pady=2)
        self.session_total_keys_label = ttk.Label(self.progress_frame, text="Total: 0")
        self.session_total_keys_label.grid(row=1, column=0, sticky="w", pady=2)
        self.scanned_label = ttk.Label(self.progress_frame, text="Keys Scanned: 0")
        self.scanned_label.grid(row=2, column=0, sticky="w", pady=2)
        self.speed_label = ttk.Label(self.progress_frame, text="Speed: 0.00 /sec")
        self.speed_label.grid(row=3, column=0, sticky="w", pady=2)
        self.session_start_label = ttk.Label(self.progress_frame, text="Session Start Key : None")
        self.session_start_label.grid(row=4, column=0, sticky="w", pady=2)
        self.remote_status = ttk.Label(self.progress_frame, text="")
        self.remote_status.grid(row=5, column=0, sticky="w", pady=2)
        # New: For remote always active
        self.remote_status.configure(text="🔗")
        self.progress_frame.columnconfigure(0, weight=1)
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=1, column=0, sticky="ew", pady=2)
        self.hide_ui_button = ttk.Button(self.button_frame, text="Hide UI", command=self.hide_ui)
        self.hide_ui_button.grid(row=0, column=0, padx=5, pady=2)
        self.button_frame.columnconfigure(3, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        self.root.update() # New: Force update to draw GUI immediately and prevent "Not Responding"
        self.update_buttons()
        self.update_gui_loop()
        last_puzzle = get_setting('last_puzzle')
        if last_puzzle:
            self.puzzle_var.set(last_puzzle)
        puzzle_no = int(self.puzzle_var.get())
        active = get_active_progress(puzzle_no)
        if active:
            self.resume_previous_scan(None)
            puzzle_no = int(self.puzzle_var.get())
            mode = active[0]['mode']
            direction = active[0]['direction']
            session_start_key = min((p['session_start_key'] for p in active if p['session_start_key']), key=lambda x: int(x,16), default='None')
            msg = (
                f"*User*: {COMPUTER_USERNAME}\n"
                "▶️ *Continuing previous scan* ▶️\n"
                f"*Puzzle*: #{puzzle_no}\n"
                f"*Mode*: {mode.capitalize()}\n"
                f"*Direction*: {direction.capitalize()}\n"
                f"*Session Start Key*: `{format_key(session_start_key)}`\n"
                f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
            )
            send_telegram_message(msg)
        else:
            msg = (
                f"*User*: {COMPUTER_USERNAME}\n"
                "✅ *No active scan found, ready to start new scan.*\n"
                f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
            )
            send_telegram_message(msg)
        self.hide_ui()
        self.start_telegram_bot()
        self.bot_monitor_thread = threading.Thread(target=self._bot_monitor, daemon=True)
        self.bot_monitor_thread.start()
        self.daily_thread = threading.Thread(target=self.daily_status_loop, daemon=True)
        self.daily_thread.start()
        self.message_sender_thread = threading.Thread(target=message_sender_loop, daemon=True)
        self.message_sender_thread.start()
        self.update_poller_thread = threading.Thread(target=update_poller, daemon=True)
        self.update_poller_thread.start()
        self.watchdog = WatchdogThread(self)
        self.watchdog.start()
        start_message = (
            f"*User*: {COMPUTER_USERNAME}\n"
            "🚀 *Script Started!* 🚀\n"
            f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
        )
        send_telegram_message(start_message)
    def load_config(self):
        config_path = os.path.join(secure_dir, "config.enc")
        if os.path.exists(config_path):
            with open(config_path, "rb") as f:
                encrypted = f.read()
            fernet = Fernet(self.key)
            try:
                decrypted = fernet.decrypt(encrypted)
                config = json.loads(decrypted.decode())
                self.multithread_var.set(config.get('multithread_enabled', False))
                self.num_threads_var.set(config.get('num_threads', CONFIG['default_num_threads']))
                logger.info(f"Loaded config: multithread={self.multithread_var.get()}, threads={self.num_threads_var.get()}")
            except Exception as e:
                logger.error(f"Failed to decrypt config: {e}, deleting invalid file")
                if os.path.exists(config_path):
                    os.remove(config_path)
                # Fall through to defaults
        else:
            num_cores = cpu_count()
            if num_cores > 6:
                self.multithread_var.set(True)
                self.num_threads_var.set(4 if num_cores > 8 else 3)
                logger.info(f"No config file, set defaults: multithread=True, threads={self.num_threads_var.get()}")
            else:
                logger.info("No config file, using default single-thread")
    def save_config(self):
        config = {
            'multithread_enabled': self.multithread_var.get(),
            'num_threads': self.num_threads_var.get()
        }
        fernet = Fernet(self.key)
        encrypted = fernet.encrypt(json.dumps(config).encode())
        config_path = os.path.join(secure_dir, "config.enc")
        with open(config_path, "wb") as f:
            f.write(encrypted)
        logger.info(f"Saved config: multithread={config['multithread_enabled']}, threads={config['num_threads']}")
    def daily_status_loop(self):
        while True:
            now = datetime.now()
            target = now.replace(hour=16, minute=12, second=0, microsecond=0)
            if now > target:
                target += timedelta(days=1)
            sleep_seconds = (target - now).total_seconds()
            time.sleep(sleep_seconds)
            self.send_daily_full_status()
    def send_daily_full_status(self):
        puzzle_no = int(self.puzzle_var.get())
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            elapsed = datetime.now() - self.script_start_time
            days = elapsed.days
            hours, remainder = divmod(elapsed.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            time_str = f"{days} days, {hours} hours, {minutes} minutes"
            first_start_key = min((t.session_start_key for t in self.scan_threads if t.session_start_key), key=lambda x: int(x, 16), default='None')
            current_last_key = max((t.session_last_key for t in self.scan_threads if t.session_last_key), key=lambda x: int(x, 16), default='None')
            total_scanned = sum(t.scanned_this_session for t in self.scan_threads)
            speed = sum(t.speed for t in self.scan_threads)
            first_timestamp = self.script_start_time.strftime('%d/%m/%Y %I:%M %p')
            mode = self.scan_threads[0].mode.capitalize() if self.scan_threads else 'None'
            direction = self.scan_threads[0].direction.capitalize() if self.scan_threads else 'None'
            msg = (
                f"{COMPUTER_USERNAME} Full Scan Details:\n"
                f"Puzzle: #{puzzle_no}\n"
                f"Mode: {mode}\n"
                f"Direction: {direction}\n"
                f"Start Key: {format_key(first_start_key)}\n"
                f"Current/Last Key: {format_key(current_last_key)}\n"
                f"First Timestamp: {first_timestamp}\n"
                f"Total Scanned Keys: {total_scanned:,}\n"
                f"Scanning Duration: {time_str}\n"
                f"Keys Speed: {speed:.2f} keys/sec"
            )
        else:
            msg = f"{COMPUTER_USERNAME} is not currently scanning."
        send_telegram_message(msg)
    def send_full_report(self):
        puzzle_no = int(self.puzzle_var.get())
        if not self.scan_threads or not any(t.is_alive() for t in self.scan_threads):
            return f"{COMPUTER_USERNAME} is not currently scanning."
        elapsed = datetime.now() - self.script_start_time
        days = elapsed.days
        hours, remainder = divmod(elapsed.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{days} days, {hours} hours, {minutes} minutes"
        first_start_key = min((t.session_start_key for t in self.scan_threads if t.session_start_key), key=lambda x: int(x, 16), default='None')
        current_last_key = max((t.session_last_key for t in self.scan_threads if t.session_last_key), key=lambda x: int(x, 16), default='None')
        total_scanned = sum(t.scanned_this_session for t in self.scan_threads)
        speed = sum(t.speed for t in self.scan_threads)
        first_timestamp = self.script_start_time.strftime('%d/%m/%Y %I:%M %p')
        mode = self.scan_threads[0].mode if self.scan_threads else 'None'
        direction = self.scan_threads[0].direction if self.scan_threads else 'None'
        msg = (
            f"{COMPUTER_USERNAME} Full Scan Details:\n"
            f"Puzzle: #{puzzle_no}\n"
            f"Mode: {mode.capitalize()}\n"
            f"Direction: {direction.capitalize()}\n"
            f"Start Key: {format_key(first_start_key)}\n"
            f"Current/Last Key: {format_key(current_last_key)}\n"
            f"First Timestamp: {first_timestamp}\n"
            f"Total Scanned Keys: {total_scanned:,}\n"
            f"Scanning Duration: {time_str}\n"
            f"Keys Speed: {speed:.2f} keys/sec"
        )
        send_telegram_message(msg)
        return msg
    def save_progress_and_report(self):
        if self.scan_threads:
            for thread in self.scan_threads:
                if thread.is_alive():
                    current_time = time.time()
                    if thread.last_chunk_key is not None:
                        thread.session_last_key = hex(thread.last_chunk_key)[2:].zfill(64)
                    elif thread.current_key is not None:
                        thread.session_last_key = hex(thread.current_key)[2:].zfill(64)
                    thread._mark_chunk()
                    save_active_progress(thread.puzzle_no, thread.thread_id, thread.current_sub_index,
                                         hex(thread.current_key)[2:].zfill(64) if thread.current_key else '0'*64,
                                         thread.mode, hex(thread.target_start_int)[2:].zfill(64),
                                         hex(thread.target_end_int)[2:].zfill(64), thread.direction,
                                         thread.current_part_index, len(thread.parts) if thread.parts else 0,
                                         thread.session_start_key, thread.session_last_key)
            self.send_full_report()
            logger.info("Saved progress and sent full report")
    def start_telegram_bot(self):
        global pending, bot_state
        pending = None
        bot_state = {}
        TGCHNG_CONFIRM, TGCHNG_NEW_TOKEN, TGCHNG_CONFIRM_NEW = range(3)
        PZL_CONFIRM = 0
        async def tgchng_start(update: Update, context: CallbackContext) -> int:
            if str(update.message.chat_id) != CHAT_ID:
                return ConversationHandler.END
            await update.message.reply_text(f"Current token: `{TELEGRAM_TOKEN}`")
            await update.message.reply_text("Do you want to change this token? (yes/no)")
            return TGCHNG_CONFIRM
        async def tgchng_confirm(update: Update, context: CallbackContext) -> int:
            text = update.message.text.strip().lower()
            if text == 'yes':
                await update.message.reply_text("Please send the new token:")
                return TGCHNG_NEW_TOKEN
            else:
                await update.message.reply_text("Change cancelled.")
                return ConversationHandler.END
        async def tgchng_new_token(update: Update, context: CallbackContext) -> int:
            new_token = update.message.text.strip()
            if ':' not in new_token:
                await update.message.reply_text("Invalid token format. Must contain ':'")
                return TGCHNG_NEW_TOKEN
            try:
                url = f"https://api.telegram.org/bot{new_token}/sendMessage"
                payload = {"chat_id": CHAT_ID, "text": "Test message from new token"}
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data['ok']:
                        context.user_data['new_token'] = new_token
                        await update.message.reply_text("Token validated successfully. Confirm change? (ok/cancel)")
                        return TGCHNG_CONFIRM_NEW
                    else:
                        await update.message.reply_text(f"Validation failed: {data.get('description', 'Unknown error')}")
                        return TGCHNG_NEW_TOKEN
                else:
                    await update.message.reply_text("Validation failed: HTTP error")
                    return TGCHNG_NEW_TOKEN
            except Exception as e:
                await update.message.reply_text(f"Validation error: {str(e)}")
                return TGCHNG_NEW_TOKEN
        async def tgchng_confirm_new(update: Update, context: CallbackContext) -> int:
            text = update.message.text.strip().lower()
            if text == 'ok':
                new_token = context.user_data['new_token']
                fernet = Fernet(load_key())
                encrypted = fernet.encrypt(new_token.encode())
                with open(token_path, "wb") as f:
                    f.write(encrypted)
                await update.message.reply_text("Token changed. Restarting script...")
                import os
                import sys
                os.execv(sys.executable, [sys.executable] + sys.argv)
                return ConversationHandler.END
            else:
                await update.message.reply_text("Change cancelled.")
                return ConversationHandler.END
        async def cancel(update: Update, context: CallbackContext) -> int:
            await update.message.reply_text("Cancelled.")
            return ConversationHandler.END
        self.conv_handler = ConversationHandler(
            entry_points=[CommandHandler('tgchng', tgchng_start)],
            states={
                TGCHNG_CONFIRM: [MessageHandler(filters.TEXT & ~filters.COMMAND, tgchng_confirm)],
                TGCHNG_NEW_TOKEN: [MessageHandler(filters.TEXT & ~filters.COMMAND, tgchng_new_token)],
                TGCHNG_CONFIRM_NEW: [MessageHandler(filters.TEXT & ~filters.COMMAND, tgchng_confirm_new)],
            },
            fallbacks=[CommandHandler('cancel', cancel)],
        )
        async def pzl_start(update: Update, context: CallbackContext) -> int:
            if str(update.message.chat_id) != CHAT_ID:
                return ConversationHandler.END
            current_no = int(self.puzzle_var.get())
            details = get_puzzle_details(current_no)
            if not details:
                await update.message.reply_text("Current puzzle details not found")
                return ConversationHandler.END
            msg = (
                f"Current puzzle: #{current_no}\n"
                f"Address: {details['address']}\n"
                f"Start: `{format_key(details['start_key'])}`\n"
                f"End: `{format_key(details['stop_key'])}`"
            )
            await update.message.reply_text(msg)
            if context.args:
                try:
                    new_no = int(context.args[0])
                    if new_no not in [p[0] for p in PUZZLES]:
                        await update.message.reply_text("Invalid puzzle number")
                        return ConversationHandler.END
                    if new_no == current_no:
                        await update.message.reply_text("Already on this puzzle, no changes made")
                        return ConversationHandler.END
                    new_details = get_puzzle_details(new_no)
                    if not new_details:
                        await update.message.reply_text("Proposed puzzle details not found")
                        return ConversationHandler.END
                    confirm_msg = (
                        f"Proposed puzzle: #{new_no}\n"
                        f"Address: {new_details['address']}\n"
                        f"Start: `{format_key(new_details['start_key'])}`\n"
                        f"End: `{format_key(new_details['stop_key'])}`\n\n"
                        "Confirm change? (ok/cancel)"
                    )
                    await update.message.reply_text(confirm_msg)
                    context.user_data['proposed_pzl'] = new_no
                    return PZL_CONFIRM
                except ValueError:
                    await update.message.reply_text("Usage: /pzl <number>")
                    return ConversationHandler.END
            else:
                await update.message.reply_text("Send /pzl <number> to change puzzle")
                return ConversationHandler.END
        async def pzl_confirm(update: Update, context: CallbackContext) -> int:
            text = update.message.text.strip().lower()
            if text == 'ok':
                new_no = context.user_data['proposed_pzl']
                self.puzzle_var.set(str(new_no))
                set_setting('last_puzzle', str(new_no))
                await update.message.reply_text(f"Puzzle changed to #{new_no}")
            else:
                await update.message.reply_text("Change cancelled")
            context.user_data.clear()
            return ConversationHandler.END
        self.pzl_conv = ConversationHandler(
            entry_points=[CommandHandler('pzl', pzl_start)],
            states={
                PZL_CONFIRM: [MessageHandler(filters.TEXT & ~filters.COMMAND, pzl_confirm)],
            },
            fallbacks=[CommandHandler('cancel', cancel)],
        )
        async def start_tgs(update: Update, context: CallbackContext) -> None:
            if str(update.message.chat_id) != CHAT_ID:
                return
            puzzle_no = int(self.puzzle_var.get())
            active = get_active_progress(puzzle_no)
            if active:
                last_key = max((p['session_last_key'] for p in active if p['session_last_key']), default='None')
                msg = f"Last scanned puzzle #{puzzle_no}, last key: {format_key(last_key)}"
            else:
                msg = "No previous scan"
            await update.message.reply_text(msg)
            if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
                await update.message.reply_text("Already a scan is ongoing. Do you want to stop it? (yes/no)")
                bot_state['waiting_stop_confirm'] = True
            else:
                await update.message.reply_text("Nothing was scanning. Enter range in format tgs/start[:end] for current puzzle, or tgs/puzzle_no/start[:end]")
                bot_state['waiting_range'] = True
        async def stop_tgs(update: Update, context: CallbackContext) -> None:
            if str(update.message.chat_id) != CHAT_ID:
                return
            self.stop_scan(silent=True)
            if self.suspended_scan:
                scan_id = self.suspended_scan
                self.suspended_scan = None
                puzzle_no = int(self.puzzle_var.get())
                recent = get_recent_scans(puzzle_no)
                scan = next((s for s in recent if s['id'] == scan_id), None)
                if scan:
                    target_start_int = int(scan['target_start'], 16)
                    target_end_int = int(scan['target_end'], 16)
                    direction = scan['direction']
                    mode = scan['mode']
                    part_index = scan['part_index']
                    num_parts = scan['num_parts']
                    parts = None
                    if mode == 'part' and num_parts > 0:
                        details = get_puzzle_details(puzzle_no)
                        start_int = int(details['start_key'], 16)
                        end_int = int(details['stop_key'], 16)
                        total = end_int - start_int + 1
                        size = total // num_parts
                        parts = []
                        for i in range(num_parts):
                            p_start = start_int + i * size
                            p_end = p_start + size - 1 if i < num_parts - 1 else end_int
                            parts.append((p_start, p_end))
                    self.start_scan(mode, target_start_int, target_end_int, direction, parts, part_index, scan_id=scan_id, is_new_scan=False, scan_type='sequential')
                    await update.message.reply_text("Remote scan stopped, resumed previous scan")
                else:
                    await update.message.reply_text("Remote scan stopped, no previous to resume")
            else:
                await update.message.reply_text("Remote scan stopped")
        async def handle_tgs_message(update: Update, context: CallbackContext) -> None:
            if str(update.message.chat_id) != CHAT_ID:
                return
            text = update.message.text.strip()
            global pending, bot_state
            if 'waiting_stop_confirm' in bot_state:
                if text.lower() == 'yes':
                    if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
                        current_scan_id = self.scan_threads[0].scan_id if self.scan_threads else None
                        if current_scan_id:
                            self.suspended_scan = current_scan_id
                        else:
                            thread = self.scan_threads[0]
                            add_recent_scan(thread.puzzle_no, thread.mode, hex(thread.target_start_int)[2:].zfill(64), hex(thread.target_end_int)[2:].zfill(64), thread.direction, 0)
                            recent = get_recent_scans(thread.puzzle_no)
                            self.suspended_scan = recent[0]['id'] if recent else None
                        self.stop_scan(silent=True)
                    del bot_state['waiting_stop_confirm']
                    await update.message.reply_text("Stopped ongoing scan. Enter range in format tgs/start[:end] or tgs/puzzle_no/start[:end]")
                    bot_state['waiting_range'] = True
                elif text.lower() == 'no':
                    del bot_state['waiting_stop_confirm']
                    await update.message.reply_text("Continuing previous scan.")
                else:
                    await update.message.reply_text("Please reply yes or no")
                return
            if pending:
                if text.lower() == 'ok':
                    puzzle_no = pending['puzzle_no']
                    self.puzzle_var.set(str(puzzle_no))
                    target_start_int = pending['start_int']
                    target_end_int = pending['end_int']
                    direction = 'forward'
                    mode = pending['mode']
                    if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
                        current_scan_id = self.scan_threads[0].scan_id if self.scan_threads else None
                        if current_scan_id:
                            self.suspended_scan = current_scan_id
                        else:
                            thread = self.scan_threads[0]
                            add_recent_scan(thread.puzzle_no, thread.mode, hex(thread.target_start_int)[2:].zfill(64), hex(thread.target_end_int)[2:].zfill(64), thread.direction, 0)
                            recent = get_recent_scans(thread.puzzle_no)
                            self.suspended_scan = recent[0]['id'] if recent else None
                        self.stop_scan(silent=True)
                    self.start_scan(mode, target_start_int, target_end_int, direction)
                    await update.message.reply_text("Scan started")
                    self.remote_status.configure(text="📡")
                    pending = None
                elif text.lower() == 'cancel':
                    await update.message.reply_text("Cancelled, ready for next command")
                    pending = None
                else:
                    await update.message.reply_text("Send OK or cancel")
                return
            if 'waiting_range' in bot_state:
                if not text.lower().startswith('tgs/'):
                    await update.message.reply_text("Please enter range in format tgs/start[:end] or tgs/puzzle_no/start[:end]")
                    return
                else:
                    del bot_state['waiting_range']
            if text.lower().startswith('tgs/'):
                after = text[4:]
                puzzle_str = None
                range_str = after
                if '/' in after:
                    p_parts = after.split('/', 1)
                    puzzle_str = p_parts[0]
                    range_str = p_parts[1]
                try:
                    if puzzle_str:
                        puzzle_no = int(puzzle_str)
                        if puzzle_no not in [p[0] for p in PUZZLES]:
                            await update.message.reply_text("Invalid puzzle no")
                            return
                    else:
                        puzzle_no = int(self.puzzle_var.get())
                    details = get_puzzle_details(puzzle_no)
                    if not details:
                        await update.message.reply_text("Puzzle details not found")
                        return
                    p_start = int(details['start_key'], 16)
                    p_end = int(details['stop_key'], 16)
                    total = p_end - p_start + 1
                    # Parse range_str
                    if ':' in range_str:
                        start_part, end_part = range_str.split(':', 1)
                        is_percent = '.' in start_part or '.' in end_part
                    else:
                        start_part = range_str
                        end_part = None
                        is_percent = '.' in start_part
                    if is_percent:
                        start_p = Decimal(start_part)
                        if end_part:
                            end_p = Decimal(end_part)
                        else:
                            end_p = Decimal('100')
                        if not (Decimal('0') <= start_p <= end_p <= Decimal('100')):
                            await update.message.reply_text("Invalid percent range: must be between 0 and 100")
                            return
                        start_int = p_start + int(Decimal(total) * (start_p / Decimal('100')))
                        end_int = p_start + int(Decimal(total) * (end_p / Decimal('100')))
                        mode = 'percent'
                    else:
                        # hex
                        start_str = start_part.lower()
                        if end_part:
                            end_str = end_part.lower()
                        else:
                            end_str = details['stop_key']
                        if not all(c in '0123456789abcdef' for c in start_str + end_str):
                            await update.message.reply_text("Invalid hex characters")
                            return
                        start_str = start_str.zfill(64)
                        end_str = end_str.zfill(64)
                        if len(start_str) > 64 or len(end_str) > 64:
                            await update.message.reply_text("Hex keys too long")
                            return
                        start_int = int(start_str, 16)
                        end_int = int(end_str, 16)
                        if not (p_start <= start_int <= end_int <= p_end):
                            await update.message.reply_text("Range out of puzzle bounds")
                            return
                        mode = 'hex'
                    key_count = end_int - start_int + 1
                    await update.message.reply_text(f"Key count: {key_count:,}\nSend OK to start or cancel")
                    pending = {'puzzle_no': puzzle_no, 'start_int': start_int, 'end_int': end_int, 'mode': mode}
                except Exception as e:
                    await update.message.reply_text(f"Error: {str(e)}")
            else:
                await update.message.reply_text("Invalid command. Send tgs/start[:end] or tgs/puzzle_no/start[:end]")
        async def error_handler(update: Update, context: CallbackContext) -> None:
            logger.error(f"Update {update} caused error {context.error}")
        self.telegram_application = ApplicationBuilder().token(TELEGRAM_TOKEN).connect_timeout(35).read_timeout(35).pool_timeout(35).build()
        self.telegram_application.add_handler(self.conv_handler)
        self.telegram_application.add_handler(self.pzl_conv)
        self.telegram_application.add_handler(CommandHandler('status', self.telegram_status))
        self.telegram_application.add_handler(CommandHandler('hello', self.telegram_hello))
        self.telegram_application.add_handler(CommandHandler('full', self.telegram_full))
        self.telegram_application.add_handler(CommandHandler('tgs', start_tgs))
        self.telegram_application.add_handler(CommandHandler('stop_tgs', stop_tgs))
        self.telegram_application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_tgs_message))
        self.telegram_application.add_handler(CommandHandler('ver', self.telegram_ver))
        self.telegram_application.add_handler(CommandHandler('info', self.telegram_info))
        self.telegram_application.add_handler(CommandHandler('enable_multi', self.telegram_enable_multi))
        self.telegram_application.add_handler(CommandHandler('disable_multi', self.telegram_disable_multi))
        self.telegram_application.add_handler(CommandHandler('set_threads', self.telegram_set_threads))
        self.telegram_application.add_handler(CommandHandler('recent', self.telegram_recent))
        self.telegram_application.add_handler(CommandHandler('continue', self.telegram_continue))
        self.telegram_application.add_handler(CommandHandler('lock', self.lock_config))
        self.telegram_application.add_handler(CommandHandler('unlock', self.unlock_config))
        self.telegram_application.add_handler(CommandHandler('restart', self.telegram_restart))
        self.telegram_application.add_handler(CommandHandler('set_status', self.telegram_set_status))
        self.telegram_application.add_handler(CommandHandler('disable_status', self.telegram_disable_status))
        self.telegram_application.add_handler(CommandHandler('enable_status', self.telegram_enable_status))
        self.telegram_application.add_handler(CommandHandler('update', self.telegram_update))
        self.telegram_application.add_handler(CommandHandler('set_update_interval', self.telegram_set_update_interval))
        self.telegram_application.add_handler(CommandHandler('set_update_urls', self.telegram_set_update_urls))
        self.telegram_application.add_handler(MessageHandler(filters.COMMAND, self.unknown_command))
        self.telegram_application.add_error_handler(error_handler)
        self.telegram_bot_thread = threading.Thread(target=self._run_bot, daemon=False)
        self.telegram_bot_thread.start()
    def _run_bot(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.bot_loop = loop
        async def run_with_retry():
            while True:
                try:
                    await self.telegram_application.initialize()
                    await self.telegram_application.start()
                    await self.telegram_application.updater.start_polling(drop_pending_updates=True, timeout=30)
                    await self.stop_async_event.wait() # Block until stop
                    break
                except NetworkError as e:
                    logger.error(f"Network error in polling: {e}", exc_info=True)
                    logger.info("Retrying in 30 seconds...")
                    await asyncio.sleep(30)
                except Exception as e:
                    logger.error(f"Unexpected error in polling: {e}", exc_info=True)
                    logger.info("Retrying in 30 seconds...")
                    await asyncio.sleep(30)
                finally:
                    try:
                        await self.telegram_application.updater.stop()
                        await self.telegram_application.stop()
                        await self.telegram_application.shutdown()
                    except Exception as cleanup_e:
                        logger.error(f"Error during cleanup: {cleanup_e}", exc_info=True)
                if self.stop_async_event.is_set():
                    break
        try:
            loop.run_until_complete(run_with_retry())
        except Exception as e:
            logger.error(f"Bot async loop crashed: {e}", exc_info=True)
    def _bot_monitor(self):
        while True:
            time.sleep(600) # Check every 10 minutes
            if not self.telegram_bot_thread.is_alive():
                logger.error("Telegram bot thread is not alive, restarting...")
                self.stop_async_event.clear() # Reset the stop event
                self.telegram_bot_thread = threading.Thread(target=self._run_bot, daemon=False)
                self.telegram_bot_thread.start()
    async def telegram_update(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        await update.message.reply_text("Checking for updates...")
        loop = asyncio.get_event_loop()
        updated = await loop.run_in_executor(None, check_and_update, False)
        if not updated:
            await update.message.reply_text("No update available or update failed.")
    async def telegram_set_update_interval(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        if not context.args:
            await update.message.reply_text("Usage: /set_update_interval <hours>")
            return
        try:
            hours = int(context.args[0])
            if hours > 0:
                set_setting('update_interval_hours', str(hours))
                await update.message.reply_text(f"Update interval set to {hours} hours.")
            else:
                await update.message.reply_text("Hours must be positive.")
        except ValueError:
            await update.message.reply_text("Invalid number.")
    async def telegram_set_update_urls(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        if len(context.args) != 2:
            await update.message.reply_text("Usage: /set_update_urls <version_url> <script_url>")
            return
        try:
            version_url = context.args[0]
            script_url = context.args[1]
            fernet = Fernet(load_key())
            encrypted_v = fernet.encrypt(version_url.encode())
            with open(update_version_url_path, "wb") as f:
                f.write(encrypted_v)
            encrypted_s = fernet.encrypt(script_url.encode())
            with open(update_script_url_path, "wb") as f:
                f.write(encrypted_s)
            global UPDATE_VERSION_URL, UPDATE_SCRIPT_URL
            UPDATE_VERSION_URL = version_url
            UPDATE_SCRIPT_URL = script_url
            await update.message.reply_text("Update URLs updated securely.")
        except Exception as e:
            logger.error(f"Failed to set update URLs: {e}")
            await update.message.reply_text("Failed to update URLs.")
    async def telegram_status(self, update: Update, context: CallbackContext) -> None:
        target = ' '.join(context.args).strip().lower() if context.args else None
        if target and COMPUTER_USERNAME.lower() != target:
            return
        puzzle_no = int(self.puzzle_var.get())
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            total_scanned = sum(t.scanned_this_session for t in self.scan_threads)
            total_speed = sum(t.speed for t in self.scan_threads)
            mode = self.scan_threads[0].mode.capitalize() if self.scan_threads else 'None'
            direction = self.scan_threads[0].direction.capitalize() if self.scan_threads else 'None'
            first_start_key = min((t.session_start_key for t in self.scan_threads if t.session_start_key), key=lambda x: int(x, 16), default='None')
            current_last_key = max((t.session_last_key for t in self.scan_threads if t.session_last_key), key=lambda x: int(x, 16), default='None')
            status_message = (
                f"{COMPUTER_USERNAME} Status:\n"
                f"Puzzle: #{puzzle_no}\n"
                f"Status: Scanning\n"
                f"Mode: {mode}\n"
                f"Direction: {direction}\n"
                f"Keys Scanned: {total_scanned:,}\n"
                f"Session Start Key: `{format_key(first_start_key)}`\n"
                f"Session Last Key: `{format_key(current_last_key)}`\n"
                f"Speed: {total_speed:.2f} keys/sec\n"
                f"Timestamp: {time.strftime('%d/%m/%Y %I:%M %p')}"
            )
        else:
            status_message = f"{COMPUTER_USERNAME} Status: Idle"
        await update.message.reply_text(status_message)
    async def telegram_hello(self, update: Update, context: CallbackContext) -> None:
        target = ' '.join(context.args).strip().lower() if context.args else None
        if target and COMPUTER_USERNAME.lower() != target:
            return
        puzzle_no = int(self.puzzle_var.get())
        multithreading = "Enabled" if self.multithread_var.get() else "Disabled"
        last_timestamp = get_last_scanned_timestamp(puzzle_no) or "None"
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            mode = self.scan_threads[0].mode if self.scan_threads else 'None'
            direction = self.scan_threads[0].direction if self.scan_threads else 'None'
            scan_status = f"Scanning: {mode.capitalize()}, {direction.capitalize()}"
        else:
            scan_status = "Idle"
        hello_message = (
            f"I'm active\n"
            f"Computer: {COMPUTER_USERNAME}\n"
            f"Multithreading: {multithreading}\n"
            f"Last scanned: {last_timestamp}\n"
            f"Status: {scan_status}"
        )
        await update.message.reply_text(hello_message)
    async def telegram_full(self, update: Update, context: CallbackContext) -> None:
        target = ' '.join(context.args).strip().lower() if context.args else None
        if target and COMPUTER_USERNAME.lower() != target:
            return
        puzzle_no = int(self.puzzle_var.get())
        if not self.scan_threads or not any(t.is_alive() for t in self.scan_threads):
            await update.message.reply_text(f"{COMPUTER_USERNAME} is not currently scanning.")
            return
        elapsed = datetime.now() - self.script_start_time
        days = elapsed.days
        hours, remainder = divmod(elapsed.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{days} days, {hours} hours, {minutes} minutes"
        first_start_key = min((t.session_start_key for t in self.scan_threads if t.session_start_key), key=lambda x: int(x, 16), default='None')
        current_last_key = max((t.session_last_key for t in self.scan_threads if t.session_last_key), key=lambda x: int(x, 16), default='None')
        total_scanned = sum(t.scanned_this_session for t in self.scan_threads)
        speed = sum(t.speed for t in self.scan_threads)
        first_timestamp = self.script_start_time.strftime('%d/%m/%Y %I:%M %p')
        mode = self.scan_threads[0].mode if self.scan_threads else 'None'
        direction = self.scan_threads[0].direction if self.scan_threads else 'None'
        msg = (
            f"{COMPUTER_USERNAME} Full Scan Details:\n"
            f"Puzzle: #{puzzle_no}\n"
            f"Mode: {mode.capitalize()}\n"
            f"Direction: {direction.capitalize()}\n"
            f"Start Key: {format_key(first_start_key)}\n"
            f"Current/Last Key: {format_key(current_last_key)}\n"
            f"First Timestamp: {first_timestamp}\n"
            f"Total Scanned Keys: {total_scanned:,}\n"
            f"Scanning Duration: {time_str}\n"
            f"Keys Speed: {speed:.2f} keys/sec"
        )
        await update.message.reply_text(msg)
    async def telegram_ver(self, update: Update, context: CallbackContext) -> None:
        await update.message.reply_text(f"Script version: {VERSION}")
    async def telegram_info(self, update: Update, context: CallbackContext) -> None:
        multi_status = "Enabled" if self.multithread_var.get() else "Disabled"
        cores = cpu_count()
        threads_count = len(self.scan_threads) if self.scan_threads else 0
        puzzle_no = self.puzzle_var.get()
        status = "Scanning" if any(t.is_alive() for t in self.scan_threads) else "Idle"
        commands = "/info, /ver, /status, /hello, /full, /tgs, /stop_tgs, /enable_multi, /disable_multi, /set_threads <num>, /recent, /continue <id>, /lock, /unlock, /restart, /set_status <minutes>, /disable_status, /enable_status, /update, /set_update_interval <hours>, /set_update_urls <version_url> <script_url>, /tgchng, /pzl"
        info_msg = f"Commands: {commands}\nMultithreading: {multi_status}\nCores: {cores}\nThreads: {threads_count}\nPuzzle: {puzzle_no}\nStatus: {status}"
        await update.message.reply_text(info_msg)
    async def telegram_enable_multi(self, update: Update, context: CallbackContext) -> None:
        if self.locked:
            await update.message.reply_text("Configuration is locked")
            return
        self.multithread_var.set(True)
        self.save_config()
        await update.message.reply_text("Multithreading enabled")
    async def telegram_disable_multi(self, update: Update, context: CallbackContext) -> None:
        if self.locked:
            await update.message.reply_text("Configuration is locked")
            return
        self.multithread_var.set(False)
        self.save_config()
        await update.message.reply_text("Multithreading disabled")
    async def telegram_set_threads(self, update: Update, context: CallbackContext) -> None:
        if self.locked:
            await update.message.reply_text("Configuration is locked")
            return
        if not context.args:
            await update.message.reply_text("Usage: /set_threads <number>")
            return
        try:
            num = int(context.args[0])
            if 1 <= num <= cpu_count():
                self.num_threads_var.set(num)
                self.save_config()
                await update.message.reply_text(f"Threads set to {num}")
            else:
                await update.message.reply_text("Invalid number")
        except:
            await update.message.reply_text("Invalid input")
    async def telegram_recent(self, update: Update, context: CallbackContext) -> None:
        puzzle_no = int(self.puzzle_var.get())
        recent = get_recent_scans(puzzle_no)
        if not recent:
            await update.message.reply_text("No recent scans")
            return
        recent = recent[:5] # Limit to last 5 to avoid message too long
        details = get_puzzle_details(puzzle_no)
        if details:
            p_start = int(details['start_key'], 16)
            p_end = int(details['stop_key'], 16)
            p_total = p_end - p_start + 1
        else:
            p_total = 1 # Avoid division by zero
        msg = f"Recent Scans for Puzzle #{puzzle_no} (last 5):\n"
        for scan in recent:
            if scan['mode'] == 'percent':
                s_start = int(scan['target_start'], 16)
                s_end = int(scan['target_end'], 16)
                percent_start = ((s_start - p_start) / p_total) * 100
                percent_end = ((s_end - p_start + 1) / p_total) * 100
                range_type = 'Percentage'
                range_str = f"{percent_start:.2f}% : {percent_end:.2f}%"
            else:
                start_key = scan['target_start']
                end_key = scan['target_end']
                formatted_start = format_key(start_key)
                formatted_end = format_key(end_key)
                range_type = 'Custom'
                range_str = f"{formatted_start} : {formatted_end}"
            msg += f"ID:{scan['id']} | {range_type} | {scan['timestamp']} | {range_str}\n"
        await update.message.reply_text(msg)
    async def telegram_continue(self, update: Update, context: CallbackContext) -> None:
        if not context.args:
            await update.message.reply_text("Usage: /continue <id>")
            return
        try:
            scan_id = int(context.args[0])
            puzzle_no = int(self.puzzle_var.get())
            recent = get_recent_scans(puzzle_no)
            scan = next((s for s in recent if s['id'] == scan_id), None)
            if not scan:
                await update.message.reply_text("Invalid ID")
                return
            if scan['completed'] and not self.allow_rescan_var.get():
                await update.message.reply_text("Scan completed, enable rescan")
                return
            target_start_int = int(scan['target_start'], 16)
            target_end_int = int(scan['target_end'], 16)
            direction = scan['direction']
            mode = scan['mode']
            part_index = scan['part_index']
            num_parts = scan['num_parts']
            parts = None
            if mode == 'part' and num_parts > 0:
                details = get_puzzle_details(puzzle_no)
                start_int = int(details['start_key'], 16)
                end_int = int(details['stop_key'], 16)
                total = end_int - start_int + 1
                size = total // num_parts
                parts = []
                for i in range(num_parts):
                    p_start = start_int + i * size
                    p_end = p_start + size - 1 if i < num_parts - 1 else end_int
                    parts.append((p_start, p_end))
            self.start_scan(mode, target_start_int, target_end_int, direction, parts, part_index, scan_id=scan_id, is_new_scan=False, scan_type='sequential')
            await update.message.reply_text("Scan continued")
        except:
            await update.message.reply_text("Error")
    async def lock_config(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        self.locked = True
        set_setting('config_locked', '1')
        self.root.after(0, self.disable_locked_controls)
        # Save current config to ensure persistence even after lock
        self.save_config()
        await update.message.reply_text("Configuration locked: puzzle no, multithreading, threads count.")
    async def unlock_config(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        self.locked = False
        set_setting('config_locked', '0')
        if not self.scan_threads or not any(t.is_alive() for t in self.scan_threads):
            self.root.after(0, self.enable_controls)
        # Save config after unlock to persist any changes
        self.save_config()
        await update.message.reply_text("Configuration unlocked.")
    async def telegram_restart(self, update: Update, context: CallbackContext) -> None:
        if str(update.message.chat_id) != CHAT_ID:
            return
        await update.message.reply_text("Saving progress and sending full report before restart...")
        self.save_progress_and_report()
        await update.message.reply_text("Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    async def telegram_set_status(self, update: Update, context: CallbackContext) -> None:
        if not context.args:
            await update.message.reply_text("Usage: /set_status <minutes>")
            return
        try:
            minutes = int(context.args[0])
            if minutes > 0:
                CONFIG['telegram_update_interval'] = minutes * 60
                await update.message.reply_text(f"Status update interval set to {minutes} minutes")
            else:
                await update.message.reply_text("Interval must be positive")
        except:
            await update.message.reply_text("Invalid number")
    async def telegram_disable_status(self, update: Update, context: CallbackContext) -> None:
        CONFIG['telegram_update_interval'] = 0
        await update.message.reply_text("Status updates disabled")
    async def telegram_enable_status(self, update: Update, context: CallbackContext) -> None:
        CONFIG['telegram_update_interval'] = 180 * 60
        await update.message.reply_text("Status updates enabled with default 180 minutes interval")
    def disable_locked_controls(self):
        pass
    def disable_controls(self):
        pass
    def enable_controls(self):
        if self.locked:
            return
    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
        logger.debug(f"Centered window: {width}x{height} at position ({x}, {y})")
    def update_buttons(self):
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            if any(t.pause_event.is_set() for t in self.scan_threads):
                pass
            else:
                pass
        else:
            pass
        logger.debug("Updated button states")
    def resume_previous_scan(self, top=None):
        puzzle_no = int(self.puzzle_var.get())
        active = get_active_progress(puzzle_no)
        if not active:
            logger.info("No previous scan to resume")
            return
        self.scan_threads = []
        mode = active[0]['mode']
        direction = active[0]['direction']
        parts = None
        if mode == 'part':
            details = get_puzzle_details(puzzle_no)
            start_int = int(details['start_key'], 16)
            end_int = int(details['stop_key'], 16)
            total = end_int - start_int + 1
            num_parts = int(active[0]['num_parts'])
            size = total // num_parts
            parts = []
            for i in range(num_parts):
                p_start = start_int + i * size
                p_end = p_start + size - 1 if i < num_parts - 1 else end_int
                parts.append((p_start, p_end))
        for progress in active:
            target_start = int(progress['target_start'], 16)
            target_end = int(progress['target_end'], 16)
            part_index = int(progress['part_index'])
            thread_id = progress['thread_id']
            details = get_puzzle_details(puzzle_no)
            thread = ScanThread(
                self, puzzle_no, target_start, target_end, direction, mode,
                details['address'], parts, part_index, thread_id, is_new_scan=False,
                allow_rescan=self.allow_rescan_var.get(), scan_type="sequential" # Assume sequential for resumed old scans
            )
            self.scan_threads.append(thread)
            thread.start()
        session_start_key = min(
            (t.session_start_key for t in self.scan_threads if t.session_start_key),
            key=lambda x: int(x, 16), default=None
        )
        details = get_puzzle_details(puzzle_no)
        puzzle_start = int(details['start_key'], 16)
        puzzle_end = int(details['stop_key'], 16)
        total = puzzle_end - puzzle_start + 1
        min_start = int(session_start_key, 16) if session_start_key else puzzle_start
        percent = ((min_start - puzzle_start) / total) * 100 if total > 0 else 0
        total_keys = sum(t.total_range_keys for t in self.scan_threads)
        self.session_total_keys_label.configure(text=f"Total: {total_keys:,}")
        self.disable_controls()
        self.update_buttons()
        logger.info(f"Resumed previous scan for puzzle {puzzle_no} with {len(self.scan_threads)} threads, allow_rescan: {self.allow_rescan_var.get()}")
    def start_scan(self, mode, target_start_int, target_end_int, direction, parts=None, part_index=0, scan_id=None, is_new_scan=True, scan_type='sequential'):
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            logger.error("Scan already in progress")
            return
        puzzle_no = int(self.puzzle_var.get())
        set_setting('last_puzzle', str(puzzle_no)) # Fix: Persist the puzzle number for resume on restart
        skips = get_skip_ranges(puzzle_no)
        to_subtract = []
        to_subtract = [(s[0], s[1]) for s in skips]
        if not self.allow_rescan_var.get():
            scanned = get_scanned_ranges(puzzle_no)
            to_subtract.extend([(s[0], s[1]) for s in scanned])
        to_subtract = merge_intervals(to_subtract)
        remaining = subtract_intervals(target_start_int, target_end_int, to_subtract)
        if not remaining:
            logger.info("The selected area is already fully scanned or skipped.")
            return
        details = get_puzzle_details(puzzle_no)
        address = details['address']
        clear_active_progress(puzzle_no)
        self.scanned_label.configure(text="Keys Scanned: 0")
        self.session_start_label.configure(text="Session Start Key: None")
        self.scan_threads = []
        total_keys = target_end_int - target_start_int + 1
        self.session_total_keys_label.configure(text=f"Total: {total_keys:,}")
        if self.multithread_var.get():
            num_threads = self.num_threads_var.get()
            keys_per_thread = total_keys // num_threads
            for i in range(num_threads):
                thread_start = target_start_int + i * keys_per_thread
                thread_end = thread_start + keys_per_thread - 1 if i < num_threads - 1 else target_end_int
                thread = ScanThread(
                    self, puzzle_no, thread_start, thread_end, direction, mode,
                    address, parts, part_index, thread_id=i, is_new_scan=is_new_scan,
                    allow_rescan=self.allow_rescan_var.get(), scan_id=scan_id, scan_type=scan_type
                )
                self.scan_threads.append(thread)
                thread.start()
            logger.info(f"Started multithreaded scan for puzzle {puzzle_no} with {num_threads} threads, allow_rescan: {self.allow_rescan_var.get()}, scan_type: {scan_type}")
        else:
            thread = ScanThread(
                self, puzzle_no, target_start_int, target_end_int, direction, mode,
                address, parts, part_index, thread_id=0, is_new_scan=is_new_scan,
                allow_rescan=self.allow_rescan_var.get(), scan_id=scan_id, scan_type=scan_type
            )
            self.scan_threads.append(thread)
            thread.start()
            logger.info(f"Started single-threaded scan for puzzle {puzzle_no}, allow_rescan: {self.allow_rescan_var.get()}, scan_type: {scan_type}")
        set_setting('last_mode', mode)
        set_setting('last_direction', direction)
        set_setting('last_target_start', hex(target_start_int)[2:].zfill(64))
        set_setting('last_target_end', hex(target_end_int)[2:].zfill(64))
        start = int(details['start_key'], 16)
        end = int(details['stop_key'], 16)
        total = end - start + 1
        session_start_key = min(
            (t.session_start_key for t in self.scan_threads if t.session_start_key),
            key=lambda x: int(x, 16), default=None
        )
        puzzle_start = int(details['start_key'], 16)
        puzzle_end = int(details['stop_key'], 16)
        total = puzzle_end - puzzle_start + 1
        min_start = int(session_start_key, 16) if session_start_key else puzzle_start
        percent = ((min_start - puzzle_start) / total) * 100 if total > 0 else 0
        self.disable_controls()
        self.update_buttons()
        start_message = (
            f"*User*: {COMPUTER_USERNAME}\n"
            "🚀 *Scan Started!* 🚀\n"
            f"*Puzzle*: #{puzzle_no}\n"
            f"*Mode*: {mode.capitalize()}\n"
            f"*Scan Type*: {scan_type.capitalize()}\n"
            f"*Threads*: {len(self.scan_threads)}\n"
            f"*Direction*: {direction.capitalize()}\n"
            f"*Session Start Key*: `{format_key(session_start_key)}`\n"
            f"*Progress*: {percent:.10f}%\n"
            f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
        )
        send_telegram_message(start_message)
        logger.info(f"Started scan for puzzle {puzzle_no} in {mode} mode with {len(self.scan_threads)} threads, allow_rescan: {self.allow_rescan_var.get()}, scan_type: {scan_type}")
    def pause_scan(self):
        for thread in self.scan_threads:
            if thread.is_alive():
                thread.pause_event.set()
        self.enable_controls()
        self.update_buttons()
        puzzle_no = int(self.puzzle_var.get())
        pause_message = (
            f"*User*: {COMPUTER_USERNAME}\n"
            "⏸️*Scan Paused* ⏸️\n"
            f"*Puzzle*: #{puzzle_no}\n"
            f"*Threads*: {len(self.scan_threads)}\n"
            f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
        )
        send_telegram_message(pause_message)
        logger.info(f"Paused scan for puzzle {puzzle_no}")
    def resume_scan(self):
        for thread in self.scan_threads:
            if thread.is_alive():
                thread.pause_event.clear()
        self.disable_controls()
        self.update_buttons()
        puzzle_no = int(self.puzzle_var.get())
        resume_message = (
            f"*User*: {COMPUTER_USERNAME}\n"
            "▶️ *Scan Resumed* ▶️\n"
            f"*Puzzle*: #{puzzle_no}\n"
            f"*Threads*: {len(self.scan_threads)}\n"
            f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
        )
        send_telegram_message(resume_message)
        logger.info(f"Resumed scan for puzzle {puzzle_no}")
    def stop_scan(self, silent=False):
        for thread in self.scan_threads:
            if thread.is_alive():
                thread.stop_event.set()
        for thread in self.scan_threads:
            thread.join() # Wait indefinitely for thread to finish
        self.scan_threads = []
        puzzle_no = int(self.puzzle_var.get())
        self.enable_controls()
        self.update_buttons()
        self.status_label.configure(text="Status: Idle")
        self.remote_status.configure(text="")
        if not silent:
            stop_message = (
                f"*User*: {COMPUTER_USERNAME}\n"
                "⏹️ *Scan Stopped* ⏹️\n"
                f"*Puzzle*: #{puzzle_no}\n"
                f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
            )
            send_telegram_message(stop_message)
        logger.info(f"Stopped scan for puzzle {puzzle_no}")
    def stop_all_threads(self):
        self.stop_scan()
    def update_gui_loop(self):
        if self.scan_threads and any(t.is_alive() for t in self.scan_threads):
            total_scanned = sum(t.scanned_this_session for t in self.scan_threads)
            total_speed = sum(t.speed for t in self.scan_threads)
            self.scanned_label.configure(text=f"Already: {total_scanned:,}")
            self.speed_label.configure(text=f"Speed: {total_speed:.2f} /sec")
            session_start_key = min(
                (t.session_start_key for t in self.scan_threads if t.session_start_key),
                key=lambda x: int(x, 16), default="None"
            )
            if session_start_key != "None":
                formatted_key = format_key(session_start_key)
            else:
                formatted_key = "None"
            self.session_start_label.configure(text=f"Start: {formatted_key}")
            puzzle_no = int(self.puzzle_var.get())
            details = get_puzzle_details(puzzle_no)
            if details:
                start_int = int(details['start_key'], 16)
                end_int = int(details['stop_key'], 16)
                total = end_int - start_int + 1
            self.status_label.configure(text="Status: Active")
        else:
            self.status_label.configure(text="Status: Idle")
            self.speed_label.configure(text="Speed: 0.00 /sec")
            self.scanned_label.configure(text="Already: 0")
            self.session_start_label.configure(text="Start: None")
            self.session_total_keys_label.configure(text="Total: 0")
        self.update_id = self.root.after(CONFIG['gui_update_ms'], self.update_gui_loop)
    def hide_ui(self):
        self.root.withdraw()
        if not self.tray_icon:
            self.create_tray_icon()
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()
    def create_tray_icon(self):
        image = Image.new('RGB', (32, 32), color=(0, 0, 255))
        draw = ImageDraw.Draw(image)
        draw.text((5, 5), "Hex", fill="white")
        self.tray_icon = pystray.Icon('Smart_solver', image, "Smart solver")
        menu = pystray.Menu(
            pystray.MenuItem("Show", self.show_ui),
        )
        self.tray_icon.menu = menu
    def show_ui(self):
        self.root.after(0, self._show_ui_internal)
    def _show_ui_internal(self):
        self.root.deiconify()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
    def toggle_threads_combo(self, *args):
        if self.locked:
            self.num_threads_combo['state'] = 'disabled'
            return
        if self.multithread_var.get():
            self.num_threads_combo['state'] = 'readonly'
        else:
            self.num_threads_combo['state'] = 'disabled'
    def on_close(self):
        self.save_progress_and_report()
        puzzle_no = int(self.puzzle_var.get())
        close_message = (
            f"*User*: {COMPUTER_USERNAME}\n"
            "⚠️*Script closed* ⚠️\n"
            f"*Puzzle*: #{puzzle_no}\n"
            f"*Threads*: {len(self.scan_threads)}\n"
            f"🕒 *Time*: {time.strftime('%d/%m/%Y %I:%M %p')}"
        )
        send_telegram_message(close_message)
        if self.telegram_application and self.bot_loop:
            def set_event():
                self.stop_async_event.set()
            self.bot_loop.call_soon_threadsafe(set_event)
        self.stop_scan(silent=True)
        if self.telegram_bot_thread and self.telegram_bot_thread.is_alive():
            self.telegram_bot_thread.join(timeout=2) # Timeout prevents indefinite hang
        if hasattr(self, 'tray_icon') and self.tray_icon:
            self.tray_icon.stop()
        # Save config on close to ensure persistence
        self.save_config()
        self.watchdog.stop_event.set()
        self.root.destroy()
    async def unknown_command(self, update: Update, context: CallbackContext) -> None:
        msg = """Supported commands:
        /status - Get current status
        /hello - Greet and basic info
        /full - Full scan details
        /ver - Script version
        /info - Commands and config info
        /enable_multi - Enable multithreading
        /disable_multi - Disable multithreading
        /set_threads <num> - Set number of threads
        /recent - List recent scans
        /continue <id> - Continue a recent scan
        /lock - Lock config
        /unlock - Unlock config
        /restart - Restart script
        /set_status <minutes> - Set status update interval
        /disable_status - Disable status updates
        /enable_status - Enable status updates
        /tgs - Start TGS mode
        /stop_tgs - Stop TGS mode
        /update - Check for script updates
        /set_update_interval <hours> - Set auto-update interval
        /set_update_urls <version_url> <script_url> - Set update URLs
        /tgchng - Change telegram token
        /pzl - Change puzzle (with number) or show current"""
        await update.message.reply_text(msg)
class WatchdogThread(threading.Thread):
    def __init__(self, gui):
        super().__init__(daemon=True)
        self.gui = gui
        self.stop_event = threading.Event()
    def run(self):
        while not self.stop_event.is_set():
            time.sleep(300) # Check every 5 minutes
            if self.gui.scan_threads:
                alive = any(t.is_alive() for t in self.gui.scan_threads)
                if not alive:
                    # Scan stopped unexpectedly
                    msg = f"*User*: {COMPUTER_USERNAME}\n⚠️ *Scan stopped unexpectedly!*\nAttempting to restart..."
                    send_telegram_message(msg)
                    # Try to restart the last scan
                    puzzle_no = int(self.gui.puzzle_var.get())
                    active = get_active_progress(puzzle_no)
                    if active:
                        self.gui.resume_previous_scan()
                    else:
                        # Or start a new one from last settings
                        details = get_puzzle_details(puzzle_no)
                        last_mode = get_setting('last_mode', 'sequential')
                        last_direction = get_setting('last_direction', 'forward')
                        last_target_start = int(get_setting('last_target_start', details['start_key']), 16)
                        last_target_end = int(get_setting('last_target_end', details['stop_key']), 16)
                        self.gui.start_scan(last_mode, last_target_start, last_target_end, last_direction)
            else:
                # No scan running, but if it should be, alert
                pass # For now, assume user controls
def shutdown_handler(signum=None, frame=None):
    global app
    logger.info("Shutdown detected, saving progress...")
    if 'app' in globals() and app:
        app.save_progress_and_report()
atexit.register(shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)
if __name__ == "__main__":
    global app
    init_db()
    vacuum_db() # New: Optimize DB at startup
    clean_active_progress()
    root = tk.Tk()
    app = HexPuzzleGUI(root)
    root.mainloop()