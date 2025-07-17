import time
import os
import bcrypt
import logging
import json
import threading
import cv2
import importlib.util
import subprocess
import shlex
import psutil
import datetime as dt
import platform
import socket
import ipaddress
import gzip
import io
import urllib3
import warnings
import shutil
import zipfile
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import Flask, Response, request, jsonify, send_file
from functools import wraps

# Папка конфигурации
CONFIG_DIR = "configs"
os.makedirs(CONFIG_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEFAULT_CONFIG = {
    "http_port": 8080,
    "https_port": 8433,
    "camera_index": 0,
    "camera_name": "cam0",
    "resolution": {
        "width": 640,
        "height": 480
    },
    "fps": 10,
    "camera_fourcc": "MJPG",
    "auth_file": "configs/auth.txt",
    "log_file": "logs/access.log",
    "log_dir": "logs",
    "log_level": "INFO",
    "max_attempts": 5,
    "attempt_window_sec": 60,
    "block_time_sec": 300,
    "use_https": True,
    "ssl_cert": "certs/cert.pem",
    "ssl_key": "certs/key.pem",
    "overlay": {
        "enabled": True,
        "text": "{camera_name} | {datetime} | {resolution} | FPS: {fps}"
    },
    "log_cleanup_enabled": True,
    "log_retention_days": 7,
    "log_cleanup_time": "03:00",
    "plugin_load_order": []
}

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)

WHITELIST_FILE = os.path.join(CONFIG_DIR, "ip_whitelist.txt")

if not os.path.exists(WHITELIST_FILE):
    default_whitelist = [
        "# Локальный хост всегда разрешён (требуется для работы некоторых функций и плагинов)",
        "127.0.0.1",
        "# Пример диапазона:",
        "# 192.168.1.0/24",
        "# Пример конкретного IP:",
        "# 10.0.0.1"
    ]
    with open(WHITELIST_FILE, 'w') as f:
        f.write("\n".join(default_whitelist))
    logging.info(f"Создан файл белого списка по умолчанию: {WHITELIST_FILE}")

with open(CONFIG_FILE) as f:
    config = json.load(f)

HTTP_PORT = config["http_port"]
HTTPS_PORT = config["https_port"]
CAMERA_INDEX = config["camera_index"]
CAMERA_FOURCC = config.get("camera_fourcc", "MJPG")
AUTH_FILE = config["auth_file"]
LOG_FILE = config["log_file"]
LOG_DIR = config["log_dir"]
LOG_LEVEL = config["log_level"]
MAX_ATTEMPTS = config["max_attempts"]
ATTEMPT_WINDOW = config["attempt_window_sec"]
BLOCK_TIME = config["block_time_sec"]
USE_HTTPS = config.get("use_https", False)
SSL_CERT = config.get("ssl_cert", "")
SSL_KEY = config.get("ssl_key", "")
CAMERA_NAME = config.get("camera_name", "Камера")
TARGET_FPS = config.get("fps", 30)
RESOLUTION = config.get("resolution", {"width": 1280, "height": 720})
OVERLAY_CONFIG = config.get("overlay", {
    "enabled": True,
    "text": "{camera_name} | {datetime} | {resolution} | FPS: {fps}"
})

# Создание auth.txt при отсутствии
if not os.path.exists(AUTH_FILE):
    with open(AUTH_FILE, 'w') as f:
        f.write("username: admin\npassword: ")
    print("[INFO] Создан файл auth.txt. Не забудьте задать пароль.")

backup_dir = os.path.join(config['log_dir'], 'config_backups')
os.makedirs(backup_dir, exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
with open(os.path.join(backup_dir, f"config_backup_start_{timestamp}.json"), 'w') as f:
    json.dump(config, f, indent=4)

logging.basicConfig(filename=LOG_FILE,
                    level=(LOG_LEVEL),
                    format='%(asctime)s - %(message)s')

def load_credentials():
    if not os.path.exists(AUTH_FILE):
        print("Файл авторизации не найден.")
        return None, None
    with open(AUTH_FILE, 'r') as f:
        lines = f.read().splitlines()
        user = lines[0].split(':')[1].strip()
        pwd_hash = lines[1].split(':')[1].strip().encode('utf-8')
        return user, pwd_hash

USERNAME, PASSWORD_HASH = load_credentials()

os.environ['PYTHONWARNINGS'] = "ignore"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = Flask(__name__)
login_attempts = {}

def load_plugins(app, config, base_path="plugins"):
    plugin_load_order = config.get("plugin_load_order", [])

    loaded = set()
    lib_plugins = []
    regular_plugins = []

    # Сканируем папки плагинов
    for plugin_name in os.listdir(base_path):
        plugin_path = os.path.join(base_path, plugin_name)
        if os.path.isdir(plugin_path):
            if plugin_name.endswith("_lib"):
                lib_plugins.append(plugin_name)
            else:
                regular_plugins.append(plugin_name)

    # Сначала загружаем плагины в порядке plugin_load_order
    for plugin_name in plugin_load_order:
        if plugin_name in loaded:
            continue
        plugin_path = os.path.join(base_path, plugin_name)
        if not os.path.isdir(plugin_path):
            logging.warning(f"[PLUGIN] '{plugin_name}' из plugin_load_order не найден.")
            continue
        _load_single_plugin(app, plugin_name, plugin_path)
        loaded.add(plugin_name)

    # Затем загружаем оставшиеся библиотеки
    for plugin_name in lib_plugins:
        if plugin_name in loaded:
            continue
        plugin_path = os.path.join(base_path, plugin_name)
        _load_single_plugin(app, plugin_name, plugin_path)
        loaded.add(plugin_name)

    # Затем обычные плагины
    for plugin_name in regular_plugins:
        if plugin_name in loaded:
            continue
        plugin_path = os.path.join(base_path, plugin_name)
        _load_single_plugin(app, plugin_name, plugin_path)
        loaded.add(plugin_name)


def _load_single_plugin(app, plugin_name, plugin_path):
    plugin_file = os.path.join(plugin_path, "plugin.py")
    config_file = os.path.join(plugin_path, "config.json")

    if not os.path.exists(plugin_file):
        logging.error(f"Плагин '{plugin_name}' не имеет plugin.py")
        return

    if not os.path.exists(config_file):
        logging.error(f"Плагин '{plugin_name}' не имеет config.json")
        return

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            plugin_config = json.load(f)
    except Exception as e:
        logging.error(f"Ошибка чтения config.json плагина '{plugin_name}': {str(e)}")
        return

    try:
        spec = importlib.util.spec_from_file_location(f"{plugin_name}_plugin", plugin_file)
        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)
    except Exception as e:
        logging.error(f"Ошибка загрузки модуля плагина '{plugin_name}': {str(e)}")
        return

    try:
        if hasattr(plugin_module, "init_plugin"):
            plugin_module.init_plugin(app, plugin_config)
            logging.info(f"Плагин '{plugin_name}' успешно загружен")
        else:
            logging.warning(f"Плагин '{plugin_name}' не содержит init_plugin. Пропускаем.")
    except Exception as e:
        logging.error(f"Ошибка инициализации плагина '{plugin_name}': {str(e)}")



def is_blocked(ip):
    if ip not in login_attempts:
        return False
    data = login_attempts[ip]
    if data["blocked_until"] and time.time() < data["blocked_until"]:
        return True
    if time.time() - data["first_attempt"] > ATTEMPT_WINDOW:
        login_attempts[ip] = {"count": 0, "first_attempt": time.time(), "blocked_until": None}
        return False
    return False

def register_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 1, "first_attempt": time.time(), "blocked_until": None}
    else:
        data = login_attempts[ip]
        data["count"] += 1
        if data["count"] > MAX_ATTEMPTS:
            data["blocked_until"] = time.time() + BLOCK_TIME

def check_auth(username, password):
    if username != USERNAME:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), PASSWORD_HASH)

def authenticate():
    return Response('Требуется авторизация', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def load_whitelist():
    """Загружает и парсит белый список из файла"""
    whitelist = []
    if not os.path.exists(WHITELIST_FILE):
        logging.critical(f"Файл белого списка {WHITELIST_FILE} не найден!")
        return []

    try:
        with open(WHITELIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                # Сохраняем все строки (включая комментарии)
                whitelist.append(line)

        # Логируем только некомментированные элементы
        active_items = [item for item in whitelist if item and not item.startswith('#')]
        logging.info(f"Загружен белый список. Активные элементы: {active_items}")
        return whitelist
    except Exception as e:
        logging.critical(f"Критическая ошибка загрузки белого списка: {str(e)}")
        return []

# Инициализация при запуске
IP_WHITELIST = load_whitelist()

def is_ip_allowed(ip):
    """Проверяет, разрешен ли IP-адрес в белом списке"""
    # Локальный хост всегда разрешен
    if ip in ["127.0.0.1", "::1", "localhost"]:
        return True

    # Загружаем актуальный белый список
    whitelist = load_whitelist()

    # Преобразуем IP в объект для сравнения
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Проверяем каждый элемент белого списка
    for item in whitelist:
        # Пропускаем комментарии и пустые строки
        item_clean = item.strip()
        if not item_clean or item_clean.startswith('#'):
            continue

        try:
            # Если это CIDR-нотация
            if '/' in item_clean:
                network = ipaddress.ip_network(item_clean, strict=False)
                if ip_obj in network:
                    return True
            # Если это конкретный IP
            else:
                # Сравниваем как строки
                if ip == item_clean:
                    return True

                # Сравниваем как объекты IP (для разных форматов)
                try:
                    item_ip = ipaddress.ip_address(item_clean)
                    if ip_obj == item_ip:
                        return True
                except ValueError:
                    continue
        except Exception as e:
            logging.error(f"Ошибка проверки элемента '{item_clean}': {str(e)}")
            continue

    return False

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        logging.debug(f"===== Начало обработки запроса от {ip} =====")
        logging.debug(f"URL: {request.url}")
        logging.debug(f"Endpoint: {request.endpoint}")

        # Принудительная проверка белого списка
        if not is_ip_allowed(ip):
            logging.warning(f"ДОСТУП ЗАПРЕЩЕН: IP {ip} не в белом списке")
            return Response('Доступ запрещен', 403)

        # Шаг 2: Проверка блокировки
        if is_blocked(ip):
            logging.warning(f"IP {ip} заблокирован")
            logging.info("===== Завершение обработки (401 Unauthorized) =====")
            return authenticate()
        else:
            logging.info(f"Проверка блокировки: IP {ip} не заблокирован")

        # Шаг 3: Проверка авторизации
        auth = request.authorization
        if not auth:
            logging.info("Запрос без авторизации")
            register_failed_attempt(ip)
            logging.info("===== Завершение обработки (401 Unauthorized) =====")
            return authenticate()

        # Проверка учетных данных
        if check_auth(auth.username, auth.password):
            logging.info(f"Успешная авторизация: {auth.username}")
            logging.info("===== Успешная авторизация, выполняем запрос =====")
            return f(*args, **kwargs)
        else:
            logging.warning(f"Неудачная авторизация: {auth.username}")
            register_failed_attempt(ip)
            logging.info("===== Завершение обработки (401 Unauthorized) =====")
            return authenticate()

    return decorated

MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
UPLOAD_FOLDER = 'uploads'
BACKUP_FOLDER = 'backups'
PLUGINS_FOLDER = 'plugins'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ...

def create_backup(source, backup_name):
    """Создает резервную копию папки"""
    backup_path = os.path.join(BACKUP_FOLDER, backup_name)
    shutil.make_archive(backup_path, 'zip', source)
    return backup_path + '.zip'

def extract_zip(zip_path, target_dir):
    """Распаковывает ZIP-архив"""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(target_dir)

def is_valid_app_update(zip_path):
    """Проверяет валидность архива с обновлением"""
    required_files = ['cameraHOST.py', 'requirements.txt']
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_files = zip_ref.namelist()
            return all(f in zip_files for f in required_files)
    except:
        return False

def is_valid_plugin(zip_path):
    """Проверяет валидность архива с плагином"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_files = zip_ref.namelist()
            # Должна быть ровно одна папка верхнего уровня
            root_dirs = [f for f in zip_files if f.endswith('/') and f.count('/') == 1]
            if len(root_dirs) != 1:
                return False

            plugin_dir = root_dirs[0]
            required_files = [f'{plugin_dir}plugin.py', f'{plugin_dir}config.json']
            return all(f in zip_files for f in required_files)
    except:
        return False

frame = None
frame_lock = threading.Lock()
last_frame = None
last_frame_lock = threading.Lock()

def capture_frames():
    global frame, last_frame

    # Инициализация состояния камеры
    with last_frame_lock:
        app.config['CAMERA_STATE'] = {
            'active': False,
            'last_frame_ref': None,
            'lock': last_frame_lock
        }

    try:
        cap = cv2.VideoCapture(CAMERA_INDEX)
        if not cap.isOpened():
            print("Не удалось открыть камеру.")
            return

        # Проверяем поддерживаемые разрешения
        supported_resolutions = [
            (640, 480), (800, 600), (1024, 768),
            (1280, 720), (1920, 1080), (3840, 2160)
        ]

        # Проверяем, поддерживается ли выбранное разрешение
        selected_res = (RESOLUTION["width"], RESOLUTION["height"])
        if selected_res not in supported_resolutions:
            logging.info(f"Разрешение {selected_res} не поддерживается, использую 640x480")
            RESOLUTION["width"], RESOLUTION["height"] = 640, 480

        supported_fourcc = {
            "MJPG": cv2.VideoWriter_fourcc('M','J','P','G'),
            "YUYV": cv2.VideoWriter_fourcc('Y','U','Y','V'),
            "H264": cv2.VideoWriter_fourcc('H','2','6','4'),
            "XVID": cv2.VideoWriter_fourcc('X','V','I','D'),
            "MP4V": cv2.VideoWriter_fourcc('M','P','4','V'),
        }

        # Выбираем кодек
        if CAMERA_FOURCC in supported_fourcc:
            fourcc_code = supported_fourcc[CAMERA_FOURCC]
        else:
            logging.warning(f"Неподдерживаемый кодек: {CAMERA_FOURCC}. Используется MJPG по умолчанию.")
            fourcc_code = supported_fourcc["MJPG"]

        # Устанавливаем параметры камеры
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, RESOLUTION["width"])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, RESOLUTION["height"])
        cap.set(cv2.CAP_PROP_FPS, TARGET_FPS)
        cap.set(cv2.CAP_PROP_FOURCC, fourcc_code)  # Используем выбранный кодек

        # Устанавливаем разрешение
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, RESOLUTION["width"])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, RESOLUTION["height"])
        cap.set(cv2.CAP_PROP_FPS, TARGET_FPS)
        cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc('M','J','P','G'))

        # Проверяем установленное разрешение
        actual_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        actual_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        logging.info(f"Установлено разрешение: {actual_width}x{actual_height}")

        # Переменные для расчета FPS
        prev_frame_time = 0
        frame_counter = 0
        last_log_time = time.time()

        # Обновляем состояние камеры
        with last_frame_lock:
            app.config['CAMERA_STATE']['active'] = True

        while True:
            start_time = time.time()

            ret, frm = cap.read()
            if not ret:
                logging.warning("Ошибка чтения кадра. Повторная инициализация камеры...")
                cap.release()
                time.sleep(1)  # Пауза перед повторной попыткой
                continue  # Перезапустите цикл

            # Добавляем наложение информации на кадр
            if OVERLAY_CONFIG.get("enabled", True):
                try:
                    # Форматируем текст
                    overlay_text = OVERLAY_CONFIG["text"]
                    overlay_text = overlay_text.replace("{camera_name}", CAMERA_NAME)
                    overlay_text = overlay_text.replace("{datetime}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    overlay_text = overlay_text.replace("{resolution}", f"{actual_width}x{actual_height}")
                    overlay_text = overlay_text.replace("{fps}", f"{actual_fps:.1f}")

                    # Параметры текста
                    font = cv2.FONT_HERSHEY_SIMPLEX
                    font_scale = 0.7
                    thickness = 2
                    color = (0, 255, 0)  # Зеленый цвет
                    bg_color = (0, 0, 0)  # Черный фон

                    # Рассчитываем размер текста
                    (text_width, text_height), baseline = cv2.getTextSize(
                        overlay_text, font, font_scale, thickness
                    )

                    # Создаем прямоугольник для фона
                    padding = 5
                    cv2.rectangle(
                        frm,
                        (0, 0),
                        (text_width + padding * 2, text_height + baseline + padding * 2),
                        bg_color,
                        -1  # Заполненный прямоугольник
                    )

                    # Добавляем текст
                    cv2.putText(
                        frm,
                        overlay_text,
                        (padding, text_height + padding),
                        font,
                        font_scale,
                        color,
                        thickness
                    )
                except Exception as e:
                    logging.error(f"Ошибка добавления текста на кадр: {str(e)}")

            # Обновление кадров
            with frame_lock:
                frame = frm
            with last_frame_lock:
                last_frame = frm.copy()
                app.config['CAMERA_STATE']['last_frame_ref'] = last_frame

            # Динамическая регулировка FPS
            elapsed = time.time() - start_time
            target_delay = 1.0 / TARGET_FPS
            sleep_time = max(0, target_delay - elapsed)
            time.sleep(sleep_time)

            # Логирование FPS каждую секунду
            frame_counter += 1
            current_time = time.time()
            if current_time - last_log_time >= 1.0:
                actual_fps = frame_counter / (current_time - last_log_time)
                logging.debug(f"Actual FPS: {actual_fps:.1f}/{TARGET_FPS}")
                frame_counter = 0
                last_log_time = current_time

    finally:
        cap.release()
        with last_frame_lock:
            app.config['CAMERA_STATE']['active'] = False

def generate_video():
    global frame
    last_time = time.time()
    frame_count = 0

    while True:
        start_time = time.time()
        with frame_lock:
            if frame is None:
                continue
            frame_copy = frame.copy()

        ret, jpeg = cv2.imencode('.jpg', frame_copy)
        if not ret:
            continue

        frame_bytes = jpeg.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        # Динамическая регулировка FPS отправки
        elapsed = time.time() - start_time
        target_delay = 1.0 / TARGET_FPS
        sleep_time = max(0, target_delay - elapsed)
        time.sleep(sleep_time)

def cleanup_old_logs():
    """Удаление старых лог-файлов согласно настройкам"""
    if not config.get("log_cleanup_enabled", True):
        return

    log_dir = config["log_dir"]
    retention_days = config.get("log_retention_days", 7)
    cutoff_time = datetime.now() - timedelta(days=retention_days)

    for filename in os.listdir(log_dir):
        if filename.startswith("access.log") or filename.startswith("config_backup"):
            continue

        filepath = os.path.join(log_dir, filename)
        if not os.path.isfile(filepath):
            continue

        file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
        if file_time < cutoff_time:
            try:
                os.remove(filepath)
                logging.info(f"Удален старый лог-файл: {filename}")
            except Exception as e:
                logging.error(f"Ошибка удаления лог-файла {filename}: {str(e)}")

def start_log_cleanup_scheduler():
    """Запуск планировщика очистки логов"""
    def scheduler_thread():
        while True:
            now = datetime.now()
            cleanup_time = config.get("log_cleanup_time", "03:00")

            try:
                # Парсим время очистки из конфига
                hour, minute = map(int, cleanup_time.split(':'))
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

                if now > next_run:
                    next_run += timedelta(days=1)

                sleep_seconds = (next_run - now).total_seconds()
                time.sleep(sleep_seconds)

                # Выполняем очистку
                cleanup_old_logs()

            except Exception as e:
                logging.error(f"Ошибка в планировщике очистки: {str(e)}")
                time.sleep(3600)  # Повторить через час при ошибке

    if config.get("log_cleanup_enabled", True):
        threading.Thread(target=scheduler_thread, daemon=True).start()

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        auth = request.authorization
        if is_blocked(ip):
            logging.info(f"[BLOCKED] {ip}")
            return authenticate()
        if not auth or not check_auth(auth.username, auth.password):
            register_failed_attempt(ip)
            user = auth.username if auth else 'None'
            logging.info(f"[FAIL] {ip} -> username='{user}'")
            return authenticate()
        logging.info(f"[OK]   {ip} -> username='{auth.username}'")
        return f(*args, **kwargs)
    return decorated

# Экспортируем декоратор для использования в плагинах
app.requires_auth = requires_auth

def run_http():
    if USE_HTTPS:
        if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
            print("❌ Не найдены SSL-сертификаты.")
            return
        context = (SSL_CERT, SSL_KEY)
        print(f"Запуск HTTPS-сервера на порту {HTTPS_PORT}")
        app.run(host='0.0.0.0', port=HTTPS_PORT, ssl_context=(SSL_CERT, SSL_KEY))
    else:
        print(f"Запуск HTTP-сервера на порту {HTTP_PORT}")
        app.run(host='0.0.0.0', port=HTTP_PORT)

@app.before_request
def check_whitelist_before_request():
    """Проверка белого списка для всех запросов"""
    # Пропускаем проверку для статических файлов
    if request.endpoint == 'static':
        return

    # Пропускаем проверку для самого белого списка
    if request.endpoint == 'white_list_config':
        return

    ip = request.remote_addr
    if not is_ip_allowed(ip):
        logging.warning(f"ДОСТУП ЗАПРЕЩЕН ДЛЯ ЗАПРОСА: {request.url} с IP {ip}")
        return Response('Доступ запрещен', 403)

def apply_auth_to_routes():
    """Применяет декоратор аутентификации ко всем маршрутам"""
    logging.info("Применение декоратора аутентификации ко всем маршрутам...")

    # Создаем словарь для отслеживания уже обработанных функций
    processed_functions = {}

    # Получаем все зарегистрированные маршруты
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        view_func = app.view_functions[endpoint]

        # Пропускаем статические файлы
        if endpoint == 'static':
            logging.debug(f"Пропускаем статический маршрут: {rule}")
            continue

        # Пропускаем сам маршрут белого списка
        if endpoint == 'white_list_config':
            logging.debug(f"Пропускаем маршрут белого списка: {rule}")
            continue

        # Получаем исходную функцию (если это метод)
        original_func = view_func
        while hasattr(original_func, '__wrapped__'):
            original_func = original_func.__wrapped__

        # Проверяем, обрабатывали ли мы уже эту функцию
        func_id = id(original_func)
        if func_id in processed_functions:
            logging.debug(f"Функция {endpoint} уже обработана")
            continue

        # Применяем декоратор
        logging.info(f"Защищаем маршрут: {endpoint} ({rule})")
        app.view_functions[endpoint] = requires_auth(view_func)

        # Помечаем как обработанную
        processed_functions[func_id] = True

    logging.info(f"Защищено маршрутов: {len(processed_functions)}")

if __name__ == '__main__':
    from flask import Flask, Response, request, render_template, redirect, url_for
    from pathlib import Path

    @app.route('/video')
    @requires_auth
    def stream_video():
        return Response(generate_video(),
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    # API для получения данных мониторинга
    @app.route('/api/monitoring')
    @requires_auth
    def api_monitoring():
        # Получаем данные о CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count(logical=False)
        cpu_count_logical = psutil.cpu_count(logical=True)

        # Получаем данные о памяти
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # Получаем данные о диске
        try:
            disk = psutil.disk_usage('/')
        except:
            disk = None

        # Получаем температуру (если доступно)
        try:
            temps = psutil.sensors_temperatures()
            cpu_temp = temps['coretemp'][0].current if 'coretemp' in temps else None
        except:
            cpu_temp = None

        # Получаем информацию о сети
        net_io = psutil.net_io_counters()

        # Получаем время работы системы
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time

        # Форматируем время работы
        uptime_str = str(uptime).split('.')[0]  # Убираем микросекунды

        # Возвращаем данные в формате JSON
        return jsonify({
            'cpu': {
                'percent': cpu_percent,
                'cores_physical': cpu_count,
                'cores_logical': cpu_count_logical
            },
            'memory': {
                'total': round(mem.total / (1024 ** 3), 2),  # в ГБ
                'used': round(mem.used / (1024 ** 3), 2),
                'free': round(mem.free / (1024 ** 3), 2),
                'percent': mem.percent
            },
            'swap': {
                'total': round(swap.total / (1024 ** 3), 2),
                'used': round(swap.used / (1024 ** 3), 2),
                'free': round(swap.free / (1024 ** 3), 2),
                'percent': swap.percent
            },
            'disk': {
                'total': round(disk.total / (1024 ** 3), 2) if disk else 0,
                'used': round(disk.used / (1024 ** 3), 2) if disk else 0,
                'free': round(disk.free / (1024 ** 3), 2) if disk else 0,
                'percent': disk.percent if disk else 0
            },
            'temperature': {
                'cpu': cpu_temp
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            },
            'system': {
                'os': platform.system(),
                'os_version': platform.version(),
                'hostname': socket.gethostname(),
                'uptime': uptime_str,
                'boot_time': boot_time.strftime("%Y-%m-%d %H:%M:%S")
            },
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })


    @app.route('/')
    @requires_auth
    def stream_page():
        return render_template('stream.html')

    @app.route('/video')
    @requires_auth
    def video_feed():
        return Response(generate_video(),
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    @app.route('/admin')
    @requires_auth
    def admin():
        return render_template('admin.html', config=config)


    @app.route('/admin/config', methods=['GET', 'POST'])
    @requires_auth
    def admin_config():
        if request.method == 'POST':
            # Обрабатываем основные параметры
            for key in config:
                if key in request.form:
                    if key == 'use_https':
                        config[key] = True if request.form.get(key) == 'on' else False
                    elif key in ['http_port', 'https_port', 'camera_index', 'max_attempts',
                                'attempt_window_sec', 'block_time_sec']:
                        config[key] = int(request.form.get(key))
                    else:
                        config[key] = request.form.get(key)

            # Обрабатываем новые параметры камеры
            config['camera_name'] = request.form.get('camera_name', 'Основная камера')
            config['fps'] = int(request.form.get('fps', 30))

            # Обрабатываем разрешение
            width = request.form.get('resolution_width')
            height = request.form.get('resolution_height')
            if width and height:
                config['resolution'] = {
                    'width': int(width),
                    'height': int(height)
                }

            # Обрабатываем оверлей
            config['overlay'] = {
                'enabled': 'overlay_enabled' in request.form,
                'text': request.form.get('overlay_text', '{camera_name} | {datetime} | {resolution} | FPS: {fps}')
            }

            config['log_cleanup_enabled'] = 'log_cleanup_enabled' in request.form
            config['log_retention_days'] = int(request.form.get('log_retention_days', 7))
            config['log_cleanup_time'] = request.form.get('log_cleanup_time', '03:00')

            plugin_order = request.form.get('plugin_load_order')
            if plugin_order:
                try:
                    config['plugin_load_order'] = json.loads(plugin_order)
                except json.JSONDecodeError:
                    flash('Ошибка формата порядка плагинов', 'error')

            # Сохраняем конфиг
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)

            return redirect(url_for('admin_config'))

        return render_template('admin_config.html', config=config)

    # Маршрут для страницы подтверждения
    @app.route('/admin/confirm_restart')
    @requires_auth
    def confirm_restart():
        return render_template('confirm_restart.html')


    @app.route('/restart', methods=['POST'])
    @requires_auth
    def restart_device():
        try:
            logging.info("[ACTION] Перезагрузка системы через веб-интерфейс")
            # Отправляем ответ до выполнения перезагрузки
            response = "Инициирована перезагрузка системы..."

            # Запускаем перезагрузку в отдельном потоке с задержкой
            def delayed_restart():
                time.sleep(3)  # Даем время для отправки ответа
                os.system("reboot")

            threading.Thread(target=delayed_restart, daemon=True).start()

            return response
        except Exception as e:
            logging.error(f"Ошибка перезагрузки: {e}")
            return f"Ошибка: {e}", 500

    @app.route('/admin/logs')
    @requires_auth
    def admin_logs():
        # Получаем текущее время для отображения
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_file = config.get("log_file", "logs/access.log")
        try:
            with open(log_file, 'r') as f:
                logs = f.read()
        except FileNotFoundError:
            logs = "Файл логов не найден"
        except Exception as e:
            logs = f"Ошибка чтения логов: {str(e)}"

        # Если запрос на обновление (через AJAX), возвращаем только содержимое логов
        if request.args.get('refresh'):
            return logs

        return render_template('logs.html', logs=logs, current_time=current_time)

    @app.route('/admin/plugins')
    @requires_auth
    def plugins_page():
        plugins = []
        plugins_dir = Path("plugins")
        protected_plugins = ["core", "security", "authentication"]

        for plugin_dir in plugins_dir.iterdir():
            if plugin_dir.is_dir():
                config_file = plugin_dir / "config.json"
                plugin_info = {
                    "name": plugin_dir.name,
                    "enabled": False,
                    "description": "Нет описания",
                    "config": {},
                    "version": "",
                    "author": "",
                    "official": False,
                    "dependencies": [],
                    "has_errors": False,
                    "error": None,
                    "missing_files": [],
                    "load_time": datetime.now().strftime("%Y-%m-%d %H:%M")
                }

                # Проверяем обязательные файлы
                required_files = ["plugin.py", "config.json"]
                missing_files = []

                for file in required_files:
                    if not (plugin_dir / file).exists():
                        missing_files.append(file)

                if missing_files:
                    plugin_info["missing_files"] = missing_files
                    plugin_info["has_errors"] = True
                    plugin_info["description"] = f"Отсутствуют файлы: {', '.join(missing_files)}"
                else:
                    try:
                        with open(config_file, "r", encoding="utf-8") as f:
                            config_data = json.load(f)
                            plugin_info["enabled"] = config_data.get("enabled", False)
                            plugin_info["description"] = config_data.get("description", "Нет описания")
                            plugin_info["version"] = config_data.get("version", "")
                            plugin_info["author"] = config_data.get("author", "")
                            plugin_info["official"] = config_data.get("official", False)
                            plugin_info["dependencies"] = config_data.get("dependencies", [])
                            plugin_info["route_url"] = config_data.get("route_url", "")

                            # Фильтруем конфиг для безопасности
                            safe_config = {}
                            sensitive_fields = ['password', 'secret', 'token', 'key']
                            for k, v in config_data.items():
                                if not any(s in k.lower() for s in sensitive_fields):
                                    safe_config[k] = v
                            plugin_info["config"] = safe_config

                    except Exception as e:
                        plugin_info["error"] = f"Ошибка чтения конфига: {str(e)}"
                        plugin_info["has_errors"] = True

                plugins.append(plugin_info)

        # Сортируем: сначала плагины с ошибками
        plugins.sort(key=lambda x: x["has_errors"], reverse=True)

        return render_template("plugins.html", plugins=plugins)

    @app.route('/admin/plugins/toggle/<plugin_name>', methods=['POST'])
    @requires_auth
    def toggle_plugin(plugin_name):
        plugins_dir = Path("plugins")
        config_path = plugins_dir / plugin_name / "config.json"

        # Проверяем существование плагина
        if not config_path.exists():
            return "Плагин не найден", 404

        try:
            # Загружаем текущую конфигурацию
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Обновляем статус
            new_status = request.form.get("enabled") == "true"
            config["enabled"] = new_status

            # Сохраняем изменения
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            # Логируем действие
            username = request.authorization.username if request.authorization else "Unknown"
            logging.info(f"[PLUGIN] Плагин '{plugin_name}' {'активирован' if new_status else 'деактивирован'} пользователем {username}")

            return "", 204  # Успешный ответ без содержимого

        except Exception as e:
            logging.error(f"Ошибка изменения статуса плагина {plugin_name}: {str(e)}")
            return f"Ошибка сервера: {str(e)}", 500

    @app.route('/admin/monitoring')
    @requires_auth
    def monitoring():
        return render_template('monitoring.html')

    if USE_HTTPS:
        print("HTTP MJPEG сервер с авторизацией на порту", HTTPS_PORT)
    else:
        print("HTTP MJPEG сервер с авторизацией на порту", HTTP_PORT)
    print("Веб-форма открывается через http://IP:PORT/")
    app.config['CAMERA_STATE'] = {
        'last_frame_ref': last_frame,
        'lock': last_frame_lock,
        'active': False
    }

    @app.route('/admin/config/white-list', methods=['GET', 'POST'])
    @requires_auth
    def white_list_config():
        # Читаем текущий белый список
        current_list = ""
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, 'r') as f:
                current_list = f.read()

        # Обработка сохранения
        if request.method == 'POST':
            new_list = request.form.get('whitelist', '')

            # Сохраняем в файл
            with open(WHITELIST_FILE, 'w') as f:
                f.write(new_list)

            # Проверяем текущий IP
            ip = request.remote_addr
            if not is_ip_allowed(ip):
                logging.error(f"Сохранение заблокировало текущий IP: {ip}")
                return Response("Вы заблокировали свой IP! Используйте другой IP для доступа.", 403)

            return redirect(url_for('white_list_config'))

        return render_template('white_list.html', whitelist=current_list)

    @app.route('/api/check-ip')
    @requires_auth
    def api_check_ip():
        ip = request.args.get('ip', request.remote_addr)
        return jsonify({
            'ip': ip,
            'allowed': is_ip_allowed(ip),
            'whitelist': load_whitelist()
        })

    @app.route('/api/plugins', methods=['GET'])
    @requires_auth
    def api_plugins():
        """API для получения списка плагинов"""
        plugins = []
        plugins_dir = Path("plugins")

        for plugin_dir in plugins_dir.iterdir():
            if plugin_dir.is_dir():
                config_file = plugin_dir / "config.json"
                plugin_info = {
                    "name": plugin_dir.name,
                    "enabled": False,
                    "description": "Нет описания",
                    "config": {}
                }

                if config_file.exists():
                    try:
                        with open(config_file, "r", encoding="utf-8") as f:
                            config_data = json.load(f)
                            plugin_info["enabled"] = config_data.get("enabled", False)
                            plugin_info["description"] = config_data.get("description", "Нет описания")
                            # Возвращаем все параметры конфига (без секретов)
                            plugin_info["config"] = {k: v for k, v in config_data.items() if k not in ["secret_key", "password"]}
                    except Exception as e:
                        plugin_info["error"] = f"Ошибка чтения конфига: {str(e)}"
                else:
                    plugin_info["error"] = "Файл config.json не найден"

                plugins.append(plugin_info)

        return jsonify({"plugins": plugins})

    @app.route('/api/plugins/<plugin_name>', methods=['POST'])
    @requires_auth
    def api_toggle_plugin(plugin_name):
        """API для включения/выключения плагина"""
        plugins_dir = Path("plugins")
        config_path = plugins_dir / plugin_name / "config.json"

        if not config_path.exists():
            return jsonify({"status": "error", "message": "Плагин не найден"}), 404

        try:
            # Получаем данные из запроса
            data = request.get_json()
            if not data or "enabled" not in data:
                return jsonify({"status": "error", "message": "Неверный запрос"}), 400

            new_status = data["enabled"]

            # Загружаем текущую конфигурацию
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Обновляем статус
            config["enabled"] = new_status

            # Сохраняем изменения
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            # Логируем действие
            username = request.authorization.username
            logging.info(f"[API][PLUGIN] Плагин '{plugin_name}' {'активирован' if new_status else 'деактивирован'} пользователем {username}")

            return jsonify({"status": "success", "enabled": new_status})

        except Exception as e:
            logging.error(f"API: Ошибка изменения статуса плагина {plugin_name}: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/api/config', methods=['GET', 'POST'])
    @requires_auth
    def api_config():
        """API для получения и изменения конфигурации"""
        global config

        if request.method == 'GET':
            # Возвращаем копию конфига без потенциально чувствительных данных
            safe_config = config.copy()
            # Удаляем чувствительные поля
            for key in ['password', 'secret', 'token']:
                if key in safe_config:
                    del safe_config[key]
            return jsonify(safe_config)

        elif request.method == 'POST':
            try:
                # Получаем данные из запроса
                data = request.get_json()
                if not data:
                    return jsonify({
                        "status": "error",
                        "message": "Неверный запрос: отсутствуют данные"
                    }), 400

                # Список запрещенных для изменения полей
                protected_fields = [
                    'auth_file', 'log_file', 'log_dir',
                    'ssl_cert', 'ssl_key', 'config_dir'
                ]

                # Проверяем, нет ли попытки изменить защищенные поля
                for field in protected_fields:
                    if field in data:
                        return jsonify({
                            "status": "error",
                            "message": f"Изменение поля '{field}' запрещено"
                        }), 403

                # Создаем резервную копию текущей конфигурации
                backup_dir = os.path.join(config['log_dir'], 'config_backups')
                os.makedirs(backup_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = os.path.join(backup_dir, f"config_{timestamp}.json")

                with open(CONFIG_FILE, 'r') as src, open(backup_file, 'w') as dst:
                    dst.write(src.read())

                # Загружаем текущий конфиг из файла
                with open(CONFIG_FILE, 'r') as f:
                    current_config = json.load(f)

                # Применяем изменения
                for key, value in data.items():
                    # Пропускаем защищенные поля (дополнительная проверка)
                    if key in protected_fields:
                        continue

                    # Специальная обработка вложенных структур
                    if key in ['resolution', 'overlay']:
                        if key not in current_config:
                            current_config[key] = {}
                        current_config[key].update(value)
                    else:
                        current_config[key] = value

                # Сохраняем обновленный конфиг
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(current_config, f, indent=4)

                # Обновляем глобальную переменную config
                config = current_config.copy()

                # Логируем действие
                username = request.authorization.username
                changed_fields = ", ".join(data.keys())
                logging.info(f"[API][CONFIG] Пользователь {username} обновил настройки: {changed_fields}")

                return jsonify({
                    "status": "success",
                    "message": "Конфигурация успешно обновлена",
                    "backup": backup_file,
                    "changed_fields": list(data.keys())
                })

            except json.JSONDecodeError:
                return jsonify({
                    "status": "error",
                    "message": "Неверный формат JSON"
                }), 400
            except Exception as e:
                logging.error(f"API: Ошибка обновления конфигурации: {str(e)}")
                return jsonify({
                    "status": "error",
                    "message": f"Ошибка обновления конфигурации: {str(e)}"
                }), 500

    @app.route('/api/restart', methods=['POST'])
    @requires_auth
    def api_restart():
        """API для перезагрузки системы"""
        try:
            logging.info("[API][ACTION] Перезагрузка системы через API")

            # Запускаем перезагрузку в отдельном потоке с задержкой
            def delayed_restart():
                time.sleep(3)
                os.system("reboot")

            threading.Thread(target=delayed_restart, daemon=True).start()

            return jsonify({
                "status": "success",
                "message": "Инициирована перезагрузка системы"
            })
        except Exception as e:
            logging.error(f"API: Ошибка перезагрузки: {e}")
            return jsonify({
                "status": "error",
                "message": f"Ошибка: {e}"
            }), 500

    @app.route('/api/logs', methods=['GET'])
    @requires_auth
    def api_get_logs():
        """API для получения информации о логах и их содержимого"""
        try:
            # Получаем параметры запроса
            lines = request.args.get('lines', default=100)
            try:
                lines = int(lines)  # Преобразуем в целое число
            except ValueError:
                lines = 100  # Значение по умолчанию при ошибке

            search = request.args.get('search', default=None)
            download = request.args.get('download', default='false').lower() == 'true'
            compressed = request.args.get('compressed', default='false').lower() == 'true'

            log_file = config.get("log_file", "logs/access.log")

            # Проверяем существование файла
            if not os.path.exists(log_file):
                return jsonify({
                    "status": "error",
                    "message": "Файл логов не найден"
                }), 404

            # Получаем информацию о файле
            file_size = os.path.getsize(log_file)
            modified_time = datetime.fromtimestamp(os.path.getmtime(log_file)).isoformat()

            # Если запрошено скачивание - возвращаем файл
            if download:
                if compressed:
                    # Создаем сжатый файл в памяти
                    buffer = io.BytesIO()
                    with open(log_file, 'rb') as f_in:
                        with gzip.GzipFile(fileobj=buffer, mode='wb') as f_out:
                            f_out.write(f_in.read())
                    buffer.seek(0)

                    return send_file(
                        buffer,
                        as_attachment=True,
                        download_name=f"camera_host_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log.gz",
                        mimetype="application/gzip"
                    )
                else:
                    return send_file(
                        log_file,
                        as_attachment=True,
                        download_name=f"camera_host_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    )

            # Читаем последние строки
            logs = []
            try:
                # Используем эффективное чтение последних N строк
                with open(log_file, 'r', encoding='utf-8') as f:
                    # Читаем все строки файла
                    all_lines = f.readlines()

                    # Берем последние N строк
                    start_index = max(0, len(all_lines) - lines)
                    logs = [line.strip() for line in all_lines[start_index:]]

                    # Фильтрация по поиску
                    if search:
                        logs = [line for line in logs if search.lower() in line.lower()]

                    # Возвращаем логи в естественном порядке (1,2,3)
                    # Уже правильный порядок - не переворачиваем!

            except UnicodeDecodeError:
                # Если возникли проблемы с кодировкой, читаем как бинарный файл
                with open(log_file, 'rb') as f:
                    all_lines = f.readlines()
                start_index = max(0, len(all_lines) - lines)
                logs = [line.decode('utf-8', errors='replace').strip()
                        for line in all_lines[start_index:]]
                if search:
                    logs = [line for line in logs if search.lower() in line.lower()]

            return jsonify({
                "status": "success",
                "file": os.path.basename(log_file),
                "path": log_file,
                "size": file_size,
                "modified": modified_time,
                "total_lines": len(logs),
                "logs": logs  # Теперь в правильном порядке
            })

        except Exception as e:
            logging.error(f"API: Ошибка чтения логов: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Ошибка чтения логов: {str(e)}"
            }), 500

    @app.route('/admin/plugins/upload', methods=['GET', 'POST'])
    @requires_auth
    def upload_plugin():
        """Страница загрузки плагинов"""
        if request.method == 'POST':
            if 'plugin_file' not in request.files:
                return render_template('plugin_upload.html', error="Файл не выбран")

            file = request.files['plugin_file']
            if file.filename == '':
                return render_template('plugin_upload.html', error="Файл не выбран")

            # Сохраняем файл
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Проверяем валидность
            if not is_valid_plugin(file_path):
                os.remove(file_path)
                return render_template('plugin_upload.html', error="Некорректный файл плагина")

            try:
                # Распаковываем плагин
                extract_zip(file_path, PLUGINS_FOLDER)
                os.remove(file_path)
                return redirect(url_for('plugins_page'))
            except Exception as e:
                return render_template('plugin_upload.html', error=f"Ошибка загрузки: {str(e)}")

        return render_template('plugin_upload.html')

    @app.route('/api/plugins/<plugin_name>/config', methods=['POST'])
    @requires_auth
    def api_update_plugin_config(plugin_name):
        """API для обновления конфигурации плагина"""
        config_path = Path("plugins") / plugin_name / "config.json"

        if not config_path.exists():
            return jsonify({
                "status": "error",
                "message": f"Плагин '{plugin_name}' не найден"
            }), 404

        try:
            # Получаем новые настройки из запроса
            new_config = request.get_json()
            if not new_config:
                return jsonify({
                    "status": "error",
                    "message": "Отсутствуют данные для обновления"
                }), 400

            # Загружаем текущий конфиг
            with open(config_path, "r", encoding="utf-8") as f:
                current_config = json.load(f)

            # Обновляем только переданные параметры
            updated_config = {**current_config, **new_config}

            # Сохраняем обновленный конфиг
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(updated_config, f, indent=4, ensure_ascii=False)

            # Логируем действие
            username = request.authorization.username
            logging.info(f"[API][PLUGIN] Конфиг плагина '{plugin_name}' обновлен пользователем {username}")

            return jsonify({
                "status": "success",
                "message": "Конфигурация успешно обновлена",
                "plugin": plugin_name
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Ошибка обновления конфига: {str(e)}"
            }), 500

    @app.route('/api/plugins/delete/<plugin_name>', methods=['POST'])
    @requires_auth
    def api_delete_plugin(plugin_name):
        """API для удаления плагина"""
        plugins_dir = Path("plugins")
        plugin_path = plugins_dir / plugin_name
        protected_plugins = ["core", "security", "authentication"]

        if plugin_name in protected_plugins:
            return jsonify({
                "status": "error",
                "message": "Этот плагин защищен от удаления"
            }), 403

        # Проверяем существование плагина
        if not plugin_path.exists() or not plugin_path.is_dir():
            return jsonify({
                "status": "error",
                "message": "Плагин не найден"
            }), 404

        try:
            # Проверяем, что это действительно папка плагина
            required_files = ["plugin.py", "config.json"]
            if not all((plugin_path / file).exists() for file in required_files):
                return jsonify({
                    "status": "error",
                    "message": "Невалидная структура плагина"
                }), 400

            # Удаляем плагин рекурсивно
            shutil.rmtree(plugin_path)

            # Логируем действие
            username = request.authorization.username
            logging.info(f"[API][PLUGIN] Плагин '{plugin_name}' удален пользователем {username}")

            return jsonify({
                "status": "success",
                "message": f"Плагин '{plugin_name}' успешно удален"
            })
        except Exception as e:
            logging.error(f"API: Ошибка удаления плагина {plugin_name}: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Ошибка удаления: {str(e)}"
            }), 500

    time.sleep(2)
    threading.Thread(target=capture_frames, daemon=True).start()
    time.sleep(3)
    load_plugins(app, config)
    time.sleep(2)
    apply_auth_to_routes()
    run_http()
    start_log_cleanup_scheduler()
