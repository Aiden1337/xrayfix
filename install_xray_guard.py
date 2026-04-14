#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import shlex
import socket
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

SERVICE_NAME = "xray-guard.service"
SHELL_URLS = [
    "https://raw.githubusercontent.com/Aiden1337/xrayfix/refs/heads/main/xray-guard.sh",
    "https://raw.githubusercontent.com/Aiden1337/xrayfix/main/xray-guard.sh",
    "https://cdn.jsdelivr.net/gh/Aiden1337/xrayfix@main/xray-guard.sh",
]

SHELL_PATH = Path("/usr/local/sbin/xray-guard.sh")
ENV_PATH = Path("/etc/default/xray-guard")
SERVICE_PATH = Path("/etc/systemd/system/xray-guard.service")


PRESETS = {
    "very-light": {
        "description": "максимально бережный режим, чтобы почти не резать легит трафик.",
        "values": {
            "PORT": "443",
            "CHECK_INTERVAL": "5",
            "CPU_THRESHOLD": "500",
            "GLOBAL_SYN": "1200",
            "GLOBAL_EST": "60000",
            "PER_IP_SYN": "40",
            "PER_IP_EST": "80",
            "NFT_CONN_LIMIT": "60",
            "NFT_RATE": "30/second",
            "NFT_BURST": "60",
            "BAN_TIMEOUT": "30m",
        },
    },
    "optimal": {
        "description": "сбалансированный режим: уже фильтрует мусор, но аккуратнее с легит трафиком.",
        "values": {
            "PORT": "443",
            "CHECK_INTERVAL": "5",
            "CPU_THRESHOLD": "320",
            "GLOBAL_SYN": "700",
            "GLOBAL_EST": "28000",
            "PER_IP_SYN": "25",
            "PER_IP_EST": "45",
            "NFT_CONN_LIMIT": "35",
            "NFT_RATE": "18/second",
            "NFT_BURST": "30",
            "BAN_TIMEOUT": "2h",
        },
    },
    "strong": {
        "description": "более жесткий режим для явной атаки, выше риск ложных банов.",
        "values": {
            "PORT": "443",
            "CHECK_INTERVAL": "5",
            "CPU_THRESHOLD": "220",
            "GLOBAL_SYN": "250",
            "GLOBAL_EST": "12000",
            "PER_IP_SYN": "15",
            "PER_IP_EST": "30",
            "NFT_CONN_LIMIT": "20",
            "NFT_RATE": "10/second",
            "NFT_BURST": "16",
            "BAN_TIMEOUT": "6h",
        },
    },
}

FIELD_HELP = {
    "PORT": "порт, который защищаем",
    "CHECK_INTERVAL": "интервал проверки в секундах",
    "CPU_THRESHOLD": "порог CPU процесса (%), после которого включается агрессивная логика",
    "GLOBAL_SYN": "глобальный порог соединений в SYN_RECV",
    "GLOBAL_EST": "глобальный порог ESTABLISHED",
    "PER_IP_SYN": "бан по числу SYN_RECV на один IP",
    "PER_IP_EST": "бан по числу ESTABLISHED на один IP",
    "NFT_CONN_LIMIT": "nftables: лимит новых TCP-соединений на IP",
    "NFT_RATE": "nftables: rate-limit новых TCP, например 18/second",
    "NFT_BURST": "nftables: burst для rate-limit",
    "BAN_TIMEOUT": "время бана, например 30m / 2h / 6h",
}


def die(msg: str, code: int = 1) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg: str) -> None:
    print(f"[i] {msg}")


def ok(msg: str) -> None:
    print(f"[OK] {msg}")


def run(cmd, check=True, capture=False):
    kwargs = {
        "check": check,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(cmd, **kwargs)


def safe_input(prompt: str, default: str = "") -> str:
    try:
        value = input(prompt)
    except EOFError:
        print()
        return default
    value = value.strip()
    if value == "":
        return default
    return value


def ask_bool(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    value = safe_input(f"{prompt} {suffix}: ", "")
    if not value:
        return default
    return value.lower() in {"y", "yes", "д", "да"}


def require_root():
    if os.geteuid() != 0:
        die("запусти установщик от root, например: sudo python3 install_xray_guard.py")


def detect_dns_issue(hostname: str = "raw.githubusercontent.com") -> bool:
    try:
        socket.gethostbyname(hostname)
        return False
    except Exception:
        return True


def download_via_curl(url: str, dst: Path) -> bool:
    if not shutil.which("curl"):
        return False
    try:
        run(["curl", "-fL", "--connect-timeout", "15", "--retry", "3", "--retry-delay", "2", url, "-o", str(dst)])
        return True
    except subprocess.CalledProcessError:
        return False


def download_via_wget(url: str, dst: Path) -> bool:
    if not shutil.which("wget"):
        return False
    try:
        run(["wget", "-O", str(dst), url])
        return True
    except subprocess.CalledProcessError:
        return False


def download_via_urllib(url: str, dst: Path) -> bool:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "xray-guard-installer/1.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()  # bytes, БЕЗ decode
        dst.write_bytes(data)
        return True
    except Exception:
        return False


def validate_shell_file(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except Exception:
        return False
    if not data:
        return False
    # Нормальная эвристика: ожидаем shebang/bash/nft/systemctl
    text = data.decode("utf-8", errors="replace")
    signatures = ["#!/", "bash", "nft", "xray-guard", "systemctl"]
    return any(sig in text for sig in signatures)


def download_shell_script(dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(prefix="xray-guard.", suffix=".tmp", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    last_error = None
    try:
        for url in SHELL_URLS:
            info(f"Пробую скачать shell-скрипт: {url}")

            if download_via_curl(url, tmp_path) or download_via_wget(url, tmp_path) or download_via_urllib(url, tmp_path):
                if validate_shell_file(tmp_path):
                    dst.write_bytes(tmp_path.read_bytes())
                    os.chmod(dst, 0o755)
                    ok(f"Shell-скрипт скачан: {dst}")
                    return url
                last_error = "скачанный файл не похож на корректный shell-скрипт"
            else:
                last_error = f"не удалось скачать: {url}"

        if detect_dns_issue():
            die(
                "не удалось скачать shell-скрипт. Похоже, на сервере проблема с DNS "
                "(не резолвится raw.githubusercontent.com). Проверь /etc/resolv.conf."
            )

        die(last_error or "не удалось скачать shell-скрипт")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def choose_preset() -> dict:
    print()
    print("Выбери пресет защиты:")
    print("  1) very-light  - очень легкая, минимум ложных банов")
    print("  2) optimal     - оптимальная, рекомендую начать с нее")
    print("  3) strong      - сильная, если идет явная атака")
    print("  4) custom      - ручная настройка")
    print()

    raw = safe_input("Твой выбор [2]: ", "2").lower()

    mapping = {
        "1": "very-light",
        "2": "optimal",
        "3": "strong",
        "4": "custom",
        "very-light": "very-light",
        "optimal": "optimal",
        "strong": "strong",
        "custom": "custom",
    }

    if raw not in mapping:
        raw = "2"

    selected = mapping[raw]

    if selected == "custom":
        base = PRESETS["optimal"]["values"].copy()
        print()
        print("Выбран режим: custom")
        print("За основу взят preset: optimal")
        return base

    print()
    print(f"Выбран пресет: {selected}")
    print(f"Описание: {PRESETS[selected]['description']}")
    return PRESETS[selected]["values"].copy()


def edit_config(config: dict) -> dict:
    print()
    print("Заполни параметры. Enter = оставить текущее значение.")
    print()

    ordered_keys = [
        "PORT",
        "CHECK_INTERVAL",
        "CPU_THRESHOLD",
        "GLOBAL_SYN",
        "GLOBAL_EST",
        "PER_IP_SYN",
        "PER_IP_EST",
        "NFT_CONN_LIMIT",
        "NFT_RATE",
        "NFT_BURST",
        "BAN_TIMEOUT",
    ]

    for key in ordered_keys:
        current = str(config[key])
        desc = FIELD_HELP.get(key, "")
        value = safe_input(f"{key} ({desc}) [{current}]: ", current)
        config[key] = value

    return config


def write_env_file(config: dict, path: Path):
    lines = [
        "# xray-guard configuration",
        "# generated by install_xray_guard.py",
        "",
    ]

    ordered_keys = [
        "PORT",
        "CHECK_INTERVAL",
        "CPU_THRESHOLD",
        "GLOBAL_SYN",
        "GLOBAL_EST",
        "PER_IP_SYN",
        "PER_IP_EST",
        "NFT_CONN_LIMIT",
        "NFT_RATE",
        "NFT_BURST",
        "BAN_TIMEOUT",
    ]

    for key in ordered_keys:
        val = str(config[key])
        lines.append(f"{key}={shlex.quote(val)}")

    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    ok(f"Env-файл записан: {path}")


def build_service_text() -> str:
    return f"""[Unit]
Description=Xray Guard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-{ENV_PATH}
ExecStart={SHELL_PATH}
Restart=always
RestartSec=3
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""


def write_service_file(path: Path):
    path.write_text(build_service_text(), encoding="utf-8")
    ok(f"Systemd unit записан: {path}")


def systemctl(*args):
    return run(["systemctl", *args])


def install():
    require_root()

    info("Установщик xray-guard")
    info(f"Shell URL: {SHELL_URLS[0]}")
    info(f"Shell path: {SHELL_PATH}")
    info(f"Env path: {ENV_PATH}")
    info(f"Service path: {SERVICE_PATH}")

    config = choose_preset()

    if ask_bool("Хочешь вручную отредактировать параметры после выбора пресета?", False):
        config = edit_config(config)

    print()
    used_url = download_shell_script(SHELL_PATH)
    info(f"Использован источник: {used_url}")

    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_env_file(config, ENV_PATH)
    write_service_file(SERVICE_PATH)

    info("Перезагружаю systemd...")
    systemctl("daemon-reload")

    info("Включаю автозапуск сервиса...")
    systemctl("enable", SERVICE_NAME)

    info("Перезапускаю сервис...")
    systemctl("restart", SERVICE_NAME)

    try:
        active = run(["systemctl", "is-active", SERVICE_NAME], capture=True).stdout.strip()
    except Exception:
        active = "unknown"

    try:
        enabled = run(["systemctl", "is-enabled", SERVICE_NAME], capture=True).stdout.strip()
    except Exception:
        enabled = "unknown"

    print()
    ok(f"Установка завершена. Service active={active}, enabled={enabled}")
    print()
    print("Полезные команды:")
    print(f"  systemctl status {SERVICE_NAME} --no-pager")
    print("  journalctl -u xray-guard.service -n 100 --no-pager")
    print("  tail -f /var/log/xray-guard.log")
    print(f"  cat {ENV_PATH}")
    print()

    if ask_bool("Показать текущий статус сервиса прямо сейчас?", True):
        print()
        try:
            run(["systemctl", "status", SERVICE_NAME, "--no-pager"])
        except subprocess.CalledProcessError:
            print("[WARN] systemctl status вернул ненулевой код, смотри журнал выше.")

    if ask_bool("Показать последние 30 строк лога xray-guard?", True):
        print()
        try:
            run(["journalctl", "-u", "xray-guard.service", "-n", "30", "--no-pager"])
        except subprocess.CalledProcessError:
            print("[WARN] Не удалось показать journalctl.")
        if Path("/var/log/xray-guard.log").exists():
            print()
            try:
                run(["tail", "-n", "30", "/var/log/xray-guard.log"])
            except subprocess.CalledProcessError:
                print("[WARN] Не удалось показать /var/log/xray-guard.log.")


def main():
    try:
        install()
    except KeyboardInterrupt:
        print("\n[ERROR] Прервано пользователем")
        sys.exit(130)
    except Exception as e:
        die(str(e))


if __name__ == "__main__":
    main()
