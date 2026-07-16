#!/usr/bin/env python3
"""
Generador de datasets sinteticos para el proyecto ProxyLogon SIEM.

Produce dos archivos:
  data/iis_logs.log       -> formato W3C Extended Log Format (IIS nativo)
  data/windows_events.log -> formato clave=valor (estilo Windows Event Log / Splunk TA-windows)

Cada evento de ataque esta anclado a un artefacto real y documentado de ProxyLogon
(CVE-2021-26855, CVE-2021-26858, CVE-2021-27065). Ver docs/00_PLAN_MAESTRO.md y
docs/01_kill_chain_artefactos.md para el detalle de cada fase.

El dataset mezcla trafico benigno de fondo con los eventos del ataque para que el
ejercicio de deteccion/triage tenga sentido real.
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible: mismo dataset cada vez que se corre

OUT_DIR = "data"

# ---------------------------------------------------------------------------
# Configuracion general de la linea de tiempo
# ---------------------------------------------------------------------------

ATTACK_DATE = datetime(2021, 3, 2, 8, 0, 0)  # fecha real del incidente ProxyLogon in-the-wild
EXCHANGE_SERVER_IP = "10.10.20.15"
EXCHANGE_HOSTNAME = "EXCH01.cfp-financiera.local"  # Corporacion Financiera del Pacifico S.A. (org ficticia)
ATTACKER_IP = "103.77.192.219"        # IOC real y publico de la campana HAFNIUM/ProxyLogon (CISA AA21-062A)
ATTACKER_C2_DOMAIN = "update-cdn-svc.net"  # dominio ficticio para el ejemplo de exfil

BENIGN_USER_IPS = [
    "192.168.1.45", "192.168.1.52", "192.168.1.61", "192.168.1.73",
    "192.168.1.88", "192.168.1.94", "192.168.1.101", "192.168.1.117",
]
BENIGN_USERS = [
    "jgarcia", "mrodriguez", "lperez", "acastro", "svargas", "dquispe", "rflores",
]
USER_AGENTS = [
    "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36",
    "Microsoft+Office/16.0+(Windows+NT+10.0;+Microsoft+Outlook+16.0.13901;+Pro)",
    "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/605.1.15",
]

# Nombre de webshell real, documentado en el CSV publico de IOCs de Splunk para
# CVE-2021-26855 (github.com/stressboi/hafnium-exchange-splunk-csvs), a su vez
# compilado de reportes de Volexity, Microsoft y Huntress Labs.
WEBSHELL_PATH = "/owa/auth/help.aspx"

# User-agent real usado por HAFNIUM para camuflar sus requests como trafico de
# un crawler legitimo (mismo CSV publico citado arriba).
ATTACKER_USER_AGENT = "DuckDuckBot/1.0;+(+http://duckduckgo.com/duckduckbot.html)"

iis_events = []   # list of dicts
win_events = []   # list of dicts


def ts_iis(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ts_win(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


# ---------------------------------------------------------------------------
# 1. Trafico benigno de fondo (IIS) - todo el dia, ruido normal
# ---------------------------------------------------------------------------

def gen_benign_iis(start, end, n):
    for _ in range(n):
        dt = start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))
        ip = random.choice(BENIGN_USER_IPS)
        user = random.choice(BENIGN_USERS)
        uri = random.choice([
            "/owa/", "/owa/auth/logon.aspx", "/ecp/", "/EWS/Exchange.asmx",
            "/Microsoft-Server-ActiveSync", "/autodiscover/autodiscover.xml",
        ])
        method = "GET" if "auth/logon" not in uri else "POST"
        iis_events.append({
            "dt": dt, "method": method, "uri": uri, "query": "-",
            "c_ip": ip, "cs_username": user if random.random() > 0.3 else "-",
            "user_agent": random.choice(USER_AGENTS), "status": 200, "substatus": 0,
            "win32_status": 0, "time_taken": random.randint(15, 400),
        })


# ---------------------------------------------------------------------------
# 2. Reconocimiento: escaneo externo buscando servidores Exchange vulnerables
# ---------------------------------------------------------------------------

def gen_recon(start):
    scan_ips = ["198.51.100.23", "198.51.100.45", "198.51.100.91"]
    for i, ip in enumerate(scan_ips):
        dt = start + timedelta(seconds=i * 4)
        iis_events.append({
            "dt": dt, "method": "GET", "uri": "/autodiscover/autodiscover.xml", "query": "-",
            "c_ip": ip, "cs_username": "-", "user_agent": "-",
            "status": 403, "substatus": 0, "win32_status": 0, "time_taken": 12,
        })


def gen_benign_windows(start, end, n):
    benign_procs = [
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe"),
        (r"C:\Program Files\Microsoft\Exchange Server\V15\bin\Microsoft.Exchange.Search.Service.exe",
         r"C:\Windows\System32\services.exe"),
        (r"C:\Windows\System32\wmiprvse.exe", r"C:\Windows\System32\svchost.exe"),
        (r"C:\Windows\System32\backgroundTaskHost.exe", r"C:\Windows\System32\svchost.exe"),
    ]
    for _ in range(n):
        dt = start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))
        new_proc, parent_proc = random.choice(benign_procs)
        win_events.append({
            "dt": dt, "event_code": 4688, "computer": EXCHANGE_HOSTNAME,
            "subject_user": "SYSTEM", "new_process_name": new_proc,
            "parent_process_name": parent_proc, "command_line": new_proc,
        })


# ---------------------------------------------------------------------------
# 3. Explotacion: CVE-2021-26855 SSRF (bypass de autenticacion)
# ---------------------------------------------------------------------------

def gen_ssrf_exploit(start):
    dt = start
    events = []
    for i in range(6):
        dt = dt + timedelta(seconds=i * 3)
        uri = "/autodiscover/autodiscover.json"
        query = f"@{ATTACKER_C2_DOMAIN}/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@{ATTACKER_C2_DOMAIN}"
        iis_events.append({
            "dt": dt, "method": "GET", "uri": uri, "query": query,
            "c_ip": ATTACKER_IP, "cs_username": "-", "user_agent": ATTACKER_USER_AGENT,
            "status": 241, "substatus": 0, "win32_status": 0, "time_taken": 8,
            "cookie": "X-AnonResource-Backend=SOME-BACKEND-FQDN~1913;X-AnonResource=true",
        })
        events.append(dt)
    return dt  # ultimo timestamp usado


# ---------------------------------------------------------------------------
# 4. Instalacion: CVE-2021-27065 escritura del webshell via /ecp/
# ---------------------------------------------------------------------------

def gen_webshell_drop(start):
    dt = start + timedelta(seconds=20)
    iis_events.append({
        "dt": dt, "method": "POST", "uri": "/ecp/proxyLogon.ecp", "query": "-",
        "c_ip": ATTACKER_IP, "cs_username": "-", "user_agent": ATTACKER_USER_AGENT,
        "status": 200, "substatus": 0, "win32_status": 0, "time_taken": 340,
        "cookie": "X-AnonResource-Backend=SOME-BACKEND-FQDN~1913;X-BEResource=SOME-BACKEND-FQDN~1913",
    })
    dt2 = dt + timedelta(seconds=15)
    iis_events.append({
        "dt": dt2, "method": "GET", "uri": WEBSHELL_PATH, "query": "-",
        "c_ip": ATTACKER_IP, "cs_username": "-", "user_agent": ATTACKER_USER_AGENT,
        "status": 200, "substatus": 0, "win32_status": 0, "time_taken": 45,
    })

    # artefacto en el host: creacion de archivo por w3wp.exe (visible como evento de proceso hijo)
    win_events.append({
        "dt": dt2 + timedelta(seconds=2), "event_code": 4663, "computer": EXCHANGE_HOSTNAME,
        "subject_user": "SYSTEM", "object_name": r"C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\help.aspx",
        "process_name": r"C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe",
        "access_mask": "WriteData",
    })
    return dt2


# ---------------------------------------------------------------------------
# 5. C2: ejecucion de comandos via webshell (IIS) + evidencia de proceso (Windows)
# ---------------------------------------------------------------------------

def gen_c2(start):
    dt = start
    commands = [
        ("whoami", "d2hvYW1p"),
        ("ipconfig /all", "aXBjb25maWcgL2FsbA=="),
        ("net user", "bmV0IHVzZXI="),
        ("powershell -enc JABjAGwAaQBlAG4AdAA...", "powershell_encoded_recon"),
    ]
    for i, (cmd, encoded) in enumerate(commands):
        dt = dt + timedelta(seconds=25 + i * 30)
        iis_events.append({
            "dt": dt, "method": "POST", "uri": WEBSHELL_PATH, "query": f"cmd={encoded[:20]}...",
            "c_ip": ATTACKER_IP, "cs_username": "-", "user_agent": ATTACKER_USER_AGENT,
            "status": 200, "substatus": 0, "win32_status": 0, "time_taken": 210,
        })
        child = "powershell.exe" if "powershell" in cmd else "cmd.exe"
        win_events.append({
            "dt": dt + timedelta(seconds=1), "event_code": 4688, "computer": EXCHANGE_HOSTNAME,
            "subject_user": "SYSTEM",
            "new_process_name": rf"C:\Windows\System32\{child}",
            "parent_process_name": r"C:\Program Files\Microsoft\Exchange Server\V15\bin\w3wp.exe",
            "command_line": f"{child} /c {cmd}",
        })
    return dt


# ---------------------------------------------------------------------------
# 6. Acciones sobre objetivos: exportacion de buzon + acceso a LSASS + exfil
# ---------------------------------------------------------------------------

def gen_actions_on_objectives(start):
    dt = start + timedelta(seconds=60)
    # Exportacion masiva de buzon via Exchange Management Shell
    win_events.append({
        "dt": dt, "event_code": 4104, "computer": EXCHANGE_HOSTNAME,
        "subject_user": "SYSTEM",
        "script_block_text": "New-MailboxExportRequest -Mailbox 'jgarcia' -FilePath '\\\\EXCH01\\C$\\inetpub\\wwwroot\\aspnet_client\\backup.pst'",
        "engine_version": "5.1",
    })

    # Acceso a LSASS desde proceso no estandar (posible procdump para credential dumping)
    dt2 = dt + timedelta(seconds=90)
    win_events.append({
        "dt": dt2, "event_code": 10, "computer": EXCHANGE_HOSTNAME,
        "source_process_name": r"C:\Windows\Temp\procdump.exe",
        "target_process_name": r"C:\Windows\System32\lsass.exe",
        "granted_access": "0x1410",
        "call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll|C:\\Windows\\System32\\KERNELBASE.dll",
    })

    # Exfiltracion: descarga del .pst via el webshell
    dt3 = dt2 + timedelta(seconds=45)
    iis_events.append({
        "dt": dt3, "method": "GET", "uri": "/aspnet_client/backup.pst", "query": "-",
        "c_ip": ATTACKER_IP, "cs_username": "-", "user_agent": ATTACKER_USER_AGENT,
        "status": 200, "substatus": 0, "win32_status": 0, "time_taken": 5200,
    })
    return dt3


# ---------------------------------------------------------------------------
# Construccion del dataset completo
# ---------------------------------------------------------------------------

def build():
    day_start = ATTACK_DATE.replace(hour=6, minute=0, second=0)
    day_end = ATTACK_DATE.replace(hour=20, minute=0, second=0)

    gen_benign_iis(day_start, day_end, n=280)
    gen_benign_windows(day_start, day_end, n=25)

    recon_start = ATTACK_DATE.replace(hour=9, minute=12, second=0)
    gen_recon(recon_start)

    ssrf_start = ATTACK_DATE.replace(hour=9, minute=45, second=0)
    last = gen_ssrf_exploit(ssrf_start)

    last = gen_webshell_drop(last)
    last = gen_c2(last)
    gen_actions_on_objectives(last)


# ---------------------------------------------------------------------------
# Escritura de archivos
# ---------------------------------------------------------------------------

def write_iis():
    iis_events.sort(key=lambda e: e["dt"])
    path = f"{OUT_DIR}/iis_logs.log"
    with open(path, "w", encoding="utf-8") as f:
        f.write("#Software: Microsoft Internet Information Services 10.0\n")
        f.write("#Version: 1.0\n")
        f.write(f"#Date: {ts_iis(ATTACK_DATE)}\n")
        f.write("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
                 "c-ip cs(User-Agent) cs(Cookie) sc-status sc-substatus sc-win32-status time-taken\n")
        for e in iis_events:
            date, time_ = ts_iis(e["dt"]).split(" ")
            line = " ".join([
                date, time_, EXCHANGE_SERVER_IP, e["method"], e["uri"], e["query"],
                "443", e["cs_username"], e["c_ip"], e["user_agent"],
                e.get("cookie", "-"), str(e["status"]), str(e["substatus"]),
                str(e["win32_status"]), str(e["time_taken"]),
            ])
            f.write(line + "\n")
    print(f"[OK] {path} -> {len(iis_events)} eventos")


def write_windows():
    win_events.sort(key=lambda e: e["dt"])
    path = f"{OUT_DIR}/windows_events.log"
    with open(path, "w", encoding="utf-8") as f:
        for e in win_events:
            fields = [f"TimeCreated={ts_win(e['dt'])}", f"EventCode={e['event_code']}",
                      f"Computer={e['computer']}"]
            for k, v in e.items():
                if k in ("dt", "event_code", "computer"):
                    continue
                key_fmt = "".join(w.capitalize() for w in k.split("_"))
                val = f'"{v}"' if " " in str(v) else v
                fields.append(f"{key_fmt}={val}")
            f.write(" ".join(fields) + "\n")
    print(f"[OK] {path} -> {len(win_events)} eventos")


if __name__ == "__main__":
    import os
    os.makedirs(OUT_DIR, exist_ok=True)
    build()
    write_iis()
    write_windows()
    print("\nListo. IOCs clave para la demo:")
    print(f"  IP atacante:      {ATTACKER_IP}")
    print(f"  Dominio C2/exfil: {ATTACKER_C2_DOMAIN}")
    print(f"  Webshell:         {WEBSHELL_PATH}")
    print(f"  Host victima:     {EXCHANGE_HOSTNAME} ({EXCHANGE_SERVER_IP})")
