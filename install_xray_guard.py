#!/usr/bin/env python3
import argparse
import os
import shutil
import stat
import subprocess
import sys
import textwrap
import urllib.request
from datetime import datetime

DEFAULT_SCRIPT_URL = "https://raw.githubusercontent.com/Aiden1337/xrayfix/refs/heads/main/xray-guard.sh"
DEFAULT_SCRIPT_PATH = "/usr/local/sbin/xray-guard.sh"
DEFAULT_ENV_PATH = "/etc/default/xray-guard"
DEFAULT_SERVICE_PATH = "/etc/systemd/system/xray-guard.service"
SERVICE_NAME = "xray-guard.service"

PRESETS = {
    "very-light": {
        "PORT": "443",
        "INTERVAL": "5",
        "CPU_THRESHOLD": "450",
        "GLOBAL_SYN_THRESHOLD": "900",
        "GLOBAL_EST_THRESHOLD": "12000",
        "PER_IP_SYN_BAN_THRESHOLD": "80",
        "PER_IP_EST_BAN_THRESHOLD": "120",
        "NFT_CONN_LIMIT": "120",
        "NFT_RATE": "30/second",
        "NFT_BURST": "80",
        "BAN_TIMEOUT": "1h",
        "TOP_LIMIT": "15",
        "LOG_FILE": "/var/log/xray-guard.log",
        "PROC_REGEX": "xray|rw-core|sing-box|v2ray",
    },
    "optimal": {
        "PORT": "443",
        "INTERVAL": "5",
        "CPU_THRESHOLD": "350",
        "GLOBAL_SYN_THRESHOLD": "500",
        "GLOBAL_EST_THRESHOLD": "7000",
        "PER_IP_SYN_BAN_THRESHOLD": "40",
        "PER_IP_EST_BAN_THRESHOLD": "60",
        "NFT_CONN_LIMIT": "80",
        "NFT_RATE": "20/second",
        "NFT_BURST": "40",
        "BAN_TIMEOUT": "2h",
        "TOP_LIMIT": "15",
        "LOG_FILE": "/var/log/xray-guard.log",
        "PROC_REGEX": "xray|rw-core|sing-box|v2ray",
    },
    "strong": {
        "PORT": "443",
        "INTERVAL": "5",
        "CPU_THRESHOLD": "250",
        "GLOBAL_SYN_THRESHOLD": "220",
        "GLOBAL_EST_THRESHOLD": "3500",
        "PER_IP_SYN_BAN_THRESHOLD": "20",
        "PER_IP_EST_BAN_THRESHOLD": "30",
        "NFT_CONN_LIMIT": "35",
        "NFT_RATE": "10/second",
        "NFT_BURST": "16",
        "BAN_TIMEOUT": "3h",
        "TOP_LIMIT": "15",
        "LOG_FILE": "/var/log/xray-guard.log",
        "PROC_REGEX": "xray|rw-core|sing-box|v2ray",
    },
}

PROMPTS = [
    ("PORT", "Порт Xray/rw-core"),
    ("INTERVAL", "Интервал проверки, сек"),
    ("CPU_THRESHOLD", "Порог CPU процесса, %"),
    ("GLOBAL_SYN_THRESHOLD", "Глобальный порог SYN-RECV"),
    ("GLOBAL_EST_THRESHOLD", "Глобальный порог ESTABLISHED"),
    ("PER_IP_SYN_BAN_THRESHOLD", "Банить IP при SYN-RECV >= "),
    ("PER_IP_EST_BAN_THRESHOLD", "Банить IP при ESTABLISHED >= "),
    ("NFT_CONN_LIMIT", "nftables: ct count over"),
    ("NFT_RATE", "nftables: rate over"),
    ("NFT_BURST", "nftables: burst packets"),
    ("BAN_TIMEOUT", "Время бана"),
    ("TOP_LIMIT", "Сколько top IP писать в лог"),
    ("LOG_FILE", "Путь к лог-файлу"),
    ("PROC_REGEX", "Regex процесса"),
]


def run(cmd, check=True, capture=False):
    kwargs = {"text": True}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, **kwargs)
    if check and result.returncode != 0:
        stderr = result.stderr.strip() if capture and result.stderr else ""
        raise RuntimeError(f"Команда упала: {' '.join(cmd)}\n{stderr}")
    return result


def require_root():
    if os.geteuid() != 0:
        print("Запусти под root:", file=sys.stderr)
        print("  sudo python3 install_xray_guard.py", file=sys.stderr)
        sys.exit(1)


def check_systemctl():
    if shutil.which("systemctl") is None:
        raise RuntimeError("systemctl не найден. Этот установщик рассчитан на systemd.")
    if shutil.which("nft") is None:
        print("Внимание: nft не найден. Скрипт установится, но защита не заработает, пока не поставишь nftables.")


def parse_env_file(path):
    data = {}
    if not os.path.exists(path):
        return data

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if len(value) >= 2 and (
                (value.startswith('"') and value.endswith('"')) or
                (value.startswith("'") and value.endswith("'"))
            ):
                value = value[1:-1]

            data[key] = value
    return data


def backup_file(path):
    if not os.path.exists(path):
        return
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{path}.bak.{ts}"
    shutil.copy2(path, backup_path)
    print(f"[i] Backup: {path} -> {backup_path}")


def download_text(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "xray-guard-installer/2.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Не удалось скачать {url}, HTTP {resp.status}")
        data = resp.read()
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        raise RuntimeError("Скачанный файл пустой")
    return text


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_file(path, content, mode=None):
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    if mode is not None:
        os.chmod(path, mode)


def env_quote(value):
    value = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value}"'


def ask(question, default, validator=None, non_interactive=False):
    if non_interactive:
        return str(default)

    while True:
        raw = input(f"{question} [{default}]: ").strip()
        value = raw if raw else str(default)

        if validator is None:
            return value

        ok, err = validator(value)
        if ok:
            return value
        print(f"  ! {err}")


def ask_yes_no(question, default=False, non_interactive=False):
    if non_interactive:
        return default

    suffix = "Y/n" if default else "y/N"
    raw = input(f"{question} [{suffix}]: ").strip().lower()

    if not raw:
        return default
    return raw in ("y", "yes", "д", "да")


def choose_preset(non_interactive=False, cli_preset=None):
    valid = ["very-light", "optimal", "strong", "custom"]

    if cli_preset:
        cli_preset = cli_preset.strip().lower()
        if cli_preset not in valid:
            raise RuntimeError(f"Неверный preset: {cli_preset}. Разрешены: {', '.join(valid)}")
        return cli_preset

    if non_interactive:
        return "optimal"

    print("Выбери пресет защиты:")
    print("  1) very-light  - очень легкая, минимум ложных банов")
    print("  2) optimal     - оптимальная, рекомендую начать с нее")
    print("  3) strong      - сильная, если идет явная атака")
    print("  4) custom      - ручная настройка")
    print("")

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

    while True:
        raw = input("Твой выбор [2]: ").strip().lower()
        if not raw:
            return "optimal"
        if raw in mapping:
            return mapping[raw]
        print("  ! Введи 1, 2, 3, 4 или имя пресета")


def validate_port(v):
    if not v.isdigit():
        return False, "Нужен integer"
    n = int(v)
    if 1 <= n <= 65535:
        return True, ""
    return False, "Порт должен быть 1..65535"


def validate_positive_int(v):
    if not v.isdigit():
        return False, "Нужен integer >= 1"
    if int(v) < 1:
        return False, "Должно быть >= 1"
    return True, ""


def validate_nonempty(v):
    if str(v).strip():
        return True, ""
    return False, "Пустое значение нельзя"


def build_cli_overrides(args):
    return {
        "PORT": args.port,
        "INTERVAL": args.interval,
        "CPU_THRESHOLD": args.cpu_threshold,
        "GLOBAL_SYN_THRESHOLD": args.global_syn_threshold,
        "GLOBAL_EST_THRESHOLD": args.global_est_threshold,
        "PER_IP_SYN_BAN_THRESHOLD": args.per_ip_syn_ban_threshold,
        "PER_IP_EST_BAN_THRESHOLD": args.per_ip_est_ban_threshold,
        "NFT_CONN_LIMIT": args.nft_conn_limit,
        "NFT_RATE": args.nft_rate,
        "NFT_BURST": args.nft_burst,
        "BAN_TIMEOUT": args.ban_timeout,
        "TOP_LIMIT": args.top_limit,
        "LOG_FILE": args.log_file,
        "PROC_REGEX": args.proc_regex,
    }


def collect_config(existing, args):
    preset = choose_preset(non_interactive=args.non_interactive, cli_preset=args.preset)

    if preset == "custom":
        base = dict(existing) if existing else dict(PRESETS["optimal"])
    else:
        base = dict(PRESETS[preset])

    validators = {
        "PORT": validate_port,
        "INTERVAL": validate_positive_int,
        "CPU_THRESHOLD": validate_positive_int,
        "GLOBAL_SYN_THRESHOLD": validate_positive_int,
        "GLOBAL_EST_THRESHOLD": validate_positive_int,
        "PER_IP_SYN_BAN_THRESHOLD": validate_positive_int,
        "PER_IP_EST_BAN_THRESHOLD": validate_positive_int,
        "NFT_CONN_LIMIT": validate_positive_int,
        "NFT_BURST": validate_positive_int,
        "TOP_LIMIT": validate_positive_int,
        "NFT_RATE": validate_nonempty,
        "BAN_TIMEOUT": validate_nonempty,
        "LOG_FILE": validate_nonempty,
        "PROC_REGEX": validate_nonempty,
    }

    cli_overrides = build_cli_overrides(args)

    if preset != "custom":
        for key, value in existing.items():
            if key in base and args.keep_existing:
                base[key] = value

    for key, value in cli_overrides.items():
        if value is not None:
            base[key] = value

    values = {}
    values["PRESET_NAME"] = preset

    if args.non_interactive:
        for key, _ in PROMPTS:
            values[key] = str(base.get(key, ""))
        return values

    print("")
    print(f"Выбран пресет: {preset}")
    if preset == "very-light":
        print("Описание: максимально бережный режим, чтобы почти не резать легит трафик.")
    elif preset == "optimal":
        print("Описание: нормальный баланс между защитой и ложными срабатываниями.")
    elif preset == "strong":
        print("Описание: агрессивнее, для периода атаки.")
    else:
        print("Описание: ручная настройка.")
    print("")

    manual_tune = True if preset == "custom" else ask_yes_no(
        "Хочешь вручную отредактировать параметры после выбора пресета?",
        default=False,
        non_interactive=args.non_interactive
    )

    if manual_tune:
        for key, label in PROMPTS:
            values[key] = ask(
                label,
                base.get(key, ""),
                validator=validators.get(key),
                non_interactive=args.non_interactive
            )
    else:
        for key, _ in PROMPTS:
            values[key] = str(base.get(key, ""))

    return values


def build_env_content(values, script_path):
    lines = [
        "# /etc/default/xray-guard",
        "# Сгенерировано установщиком xray-guard",
        f"# Script: {script_path}",
        f"# Preset: {values.get('PRESET_NAME', 'unknown')}",
        "",
    ]
    for key, _ in PROMPTS:
        lines.append(f"{key}={env_quote(values[key])}")
    lines.append("")
    return "\n".join(lines)


def build_service_content(script_path, env_path):
    return textwrap.dedent(f"""\
        [Unit]
        Description=Xray Guard auto-ban service
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        EnvironmentFile=-{env_path}
        ExecStart={script_path}
        Restart=always
        RestartSec=2
        KillMode=process

        [Install]
        WantedBy=multi-user.target
    """)


def install_script(script_url, script_path):
    print(f"[i] Скачиваю shell-скрипт: {script_url}")
    content = download_text(script_url)

    required_markers = [
        "PORT=",
        "PROC_REGEX=",
        "BAN_TIMEOUT",
    ]
    missing = [m for m in required_markers if m not in content]
    if missing:
        raise RuntimeError(
            "Скачанный xray-guard.sh не похож на ожидаемый файл. "
            f"Не найдены маркеры: {', '.join(missing)}"
        )

    backup_file(script_path)
    write_file(script_path, content, mode=0o755)

    st = os.stat(script_path)
    os.chmod(script_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[ok] Установлен {script_path}")


def install_env(env_path, env_content):
    backup_file(env_path)
    write_file(env_path, env_content, mode=0o644)
    print(f"[ok] Записан env-файл {env_path}")


def install_service(service_path, service_content):
    backup_file(service_path)
    write_file(service_path, service_content, mode=0o644)
    print(f"[ok] Записан systemd unit {service_path}")


def enable_and_start_service():
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", SERVICE_NAME])
    run(["systemctl", "restart", SERVICE_NAME])

    active = run(["systemctl", "is-active", SERVICE_NAME], check=False, capture=True)
    status = active.stdout.strip() if active.stdout else "unknown"

    if status != "active":
        print("[!] Сервис не стал active. Показываю статус:")
        run(["systemctl", "status", SERVICE_NAME, "--no-pager", "-l"], check=False)
        raise RuntimeError("Сервис не запустился нормально")

    print(f"[ok] Сервис {SERVICE_NAME} активен")


def print_summary(values, script_path, env_path, service_path):
    print("\n====== ГОТОВО ======")
    print(f"Preset       : {values.get('PRESET_NAME', 'unknown')}")
    print(f"Shell script : {script_path}")
    print(f"Env file     : {env_path}")
    print(f"Service      : {service_path}")
    print("")
    print("Текущие настройки:")
    for key, _ in PROMPTS:
        print(f"  {key}={values[key]}")
    print("")
    print("Полезные команды:")
    print(f"  systemctl status {SERVICE_NAME} --no-pager -l")
    print(f"  journalctl -u {SERVICE_NAME} -f")
    print(f"  tail -f {values['LOG_FILE']}")
    print(f"  systemctl restart {SERVICE_NAME}")
    print(f"  systemctl stop {SERVICE_NAME}")
    print(f"  systemctl disable --now {SERVICE_NAME}")
    print("")


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Установщик xray-guard.sh + systemd service + presets"
    )

    p.add_argument("--script-url", default=DEFAULT_SCRIPT_URL, help="RAW URL shell-скрипта")
    p.add_argument("--script-path", default=DEFAULT_SCRIPT_PATH, help="Куда ставить xray-guard.sh")
    p.add_argument("--env-path", default=DEFAULT_ENV_PATH, help="Путь env-файла")
    p.add_argument("--service-path", default=DEFAULT_SERVICE_PATH, help="Путь systemd unit")
    p.add_argument("--non-interactive", action="store_true", help="Не спрашивать значения, взять preset/CLI/defaults")
    p.add_argument("--preset", choices=["very-light", "optimal", "strong", "custom"], help="Пресет настроек")
    p.add_argument("--keep-existing", action="store_true", help="Если есть старый env-файл, использовать его значения поверх пресета")

    p.add_argument("--port")
    p.add_argument("--interval")
    p.add_argument("--cpu-threshold")
    p.add_argument("--global-syn-threshold")
    p.add_argument("--global-est-threshold")
    p.add_argument("--per-ip-syn-ban-threshold")
    p.add_argument("--per-ip-est-ban-threshold")
    p.add_argument("--nft-conn-limit")
    p.add_argument("--nft-rate")
    p.add_argument("--nft-burst")
    p.add_argument("--ban-timeout")
    p.add_argument("--top-limit")
    p.add_argument("--log-file")
    p.add_argument("--proc-regex")

    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    require_root()
    check_systemctl()

    existing = parse_env_file(args.env_path)

    print("[i] Установщик xray-guard")
    print(f"[i] Shell URL: {args.script_url}")
    print(f"[i] Shell path: {args.script_path}")
    print(f"[i] Env path: {args.env_path}")
    print(f"[i] Service path: {args.service_path}")
    print("")

    values = collect_config(existing, args)

    install_script(args.script_url, args.script_path)

    env_content = build_env_content(values, args.script_path)
    install_env(args.env_path, env_content)

    service_content = build_service_content(args.script_path, args.env_path)
    install_service(args.service_path, service_content)

    enable_and_start_service()
    print_summary(values, args.script_path, args.env_path, args.service_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
