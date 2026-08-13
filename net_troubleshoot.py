#!/usr/bin/env python3
"""
net_troubleshoot.py - Diagnostico completo de conectividade de rede
==============================================================
Cobre: Camada 2 (adaptador) -> Camada 3 (IP/ICMP) -> Camada 4 (TCP/UDP)
       -> Camada 5-7 (DNS, HTTP, HTTPS, proxy, hosts, MTU)

Uso:  python net_troubleshoot.py                    (modo padrao)
      python net_troubleshoot.py --host site.com.br (testa host especifico)
      python net_troubleshoot.py --json relatorio.json (salva JSON)
      python net_troubleshoot.py --log  (salva log em arquivo)
"""

import os
import sys
import json
import time
import socket
import struct
import subprocess
import platform
import threading
import argparse
import urllib.request
import urllib.error
import datetime as dt
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# CONSTANTES E CONFIGURACAO
# ============================================================
IS_WINDOWS = platform.system().lower().startswith("win")

DNS_SERVERS = [
    ("Sistema (padrao)",   None),
    ("Google DNS",         "8.8.8.8"),
    ("Cloudflare",         "1.1.1.1"),
    ("Quad9",              "9.9.9.9"),
    ("OpenDNS",            "208.67.222.222"),
]

PING_TARGETS = [
    ("Gateway padrao (detectado)", "__GATEWAY__"),
    ("Cloudflare (1.1.1.1)",       "1.1.1.1"),
    ("Google DNS (8.8.8.8)",       "8.8.8.8"),
    ("Google DNS2 (8.8.4.4)",      "8.8.4.4"),
    ("Quad9 (9.9.9.9)",            "9.9.9.9"),
]

TEST_DOMAINS = [
    "google.com.br",
    "cloudflare.com",
    "microsoft.com",
    "lan.rnp.br",
]

TEST_HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts" if IS_WINDOWS else "/etc/hosts"

HTTP_TESTS = [
    ("http://clients3.google.com/generate_204",  204),
    ("http://detectportal.firefox.com/success.txt", 200),
    ("http://www.msftconnecttest.com/connecttest.txt", 200),
    ("https://www.google.com",                  200),
    ("https://cloudflare.com",                  301),
]

COMMON_PORTS = [
    ("DNS (UDP/TCP 53)",    53),
    ("HTTP (TCP 80)",       80),
    ("HTTPS (TCP 443)",     443),
    ("SMB (TCP 445)",       445),
    ("RDP (TCP 3389)",      3389),
]

BANNER = r"""
  _   _      _   _____ _      _   ___ ___ _  _ _____ _   _  ___ _____
 | \ | |    /_\ |_   _| |    /_\ / __| __| \| |_   _| | | |/ _ \_   _|
 |  \| |   / _ \  | | | |__ / _ \\__ \ _|| .` | | | | |_| | (_) || |
 |_|\_|__/_/ \_\ |_| |____/_/ \_\___/___|_|\_| |_|  \___/ \___/ |_|
     |___/    T R O U B L E S H O O T   D E   R E D E   v1.0

"""

OK = "\033[92m[ OK  ]\033[0m"
FAIL = "\033[91m[FAIL ]\033[0m"
WARN = "\033[93m[WARN ]\033[0m"
INFO = "\033[94m[INFO ]\033[0m"
HEAD = "\033[96m[ ---- ]\033[0m"

if not IS_WINDOWS:
    try:
        import colorama
        colorama.init()
    except Exception:
        pass
else:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass
    try:
        import sys as _sys
        if hasattr(_sys.stdout, "reconfigure"):
            _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(_sys.stderr, "reconfigure"):
            _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def sanitize(text):
    if not isinstance(text, str):
        return text
    try:
        return text.encode("cp1252", errors="replace").decode("cp1252", errors="replace")
    except Exception:
        return text.encode("ascii", errors="replace").decode("ascii", errors="replace")


# ============================================================
# UTILITARIOS
# ============================================================
class Logger:
    def __init__(self, log_path=None):
        self.log_path = log_path
        self.lines = []
        self.lock = threading.Lock()

    def log(self, msg):
        with self.lock:
            clean = msg
            for esc in ("\033[92m", "\033[91m", "\033[93m", "\033[94m",
                        "\033[96m", "\033[0m"):
                clean = clean.replace(esc, "")
            self.lines.append(clean)
            try:
                print(msg)
            except UnicodeError:
                print(sanitize(msg))

    def __call__(self, msg):
        self.log(msg)

    def save(self):
        if self.log_path:
            Path(self.log_path).write_text("\n".join(self.lines), encoding="utf-8")
            return True
        return False


def run_cmd(cmd, timeout=8):
    try:
        enc = "utf-8" if IS_WINDOWS else None
        res = subprocess.run(
            cmd, capture_output=True, encoding=enc, errors="replace", timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        return out + (("\n" + err) if err else "") or None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return "<TIMEOUT>"
    except Exception as e:
        return f"<ERRO: {e}>"


def banner(log, title):
    bar = "=" * 72
    log(f"\n{HEAD} {title}")
    log(f"{HEAD} {bar}")


# ============================================================
# CAMADA 1-2: Adaptador, IP, Gateway, DHCP
# ============================================================
def detect_gateway_windows(log):
    out = run_cmd(["ipconfig"])
    if not out:
        return None
    gw = None
    for line in out.splitlines():
        line = line.strip()
        if "Gateway" in line and "Padrao" in line or "Default Gateway" in line:
            parts = [p for p in line.split(":") if len(p) > 1]
            if len(parts) >= 2:
                for candidate in parts[-1].replace(",", " ").split():
                    if "." in candidate and ":" not in candidate:
                        return candidate
    return gw


def detect_gateway_unix(log):
    for cmd in (["ip", "route"], ["route", "-n"]):
        out = run_cmd(cmd)
        if not out:
            continue
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] in ("default", "0.0.0.0"):
                for w in parts:
                    if "." in w and ":" not in w and len(w) > 6:
                        return w
    return None


def list_interfaces(log):
    ifaces = []
    if IS_WINDOWS:
        out = run_cmd(["netsh", "interface", "ipv4", "show", "interfaces"])
        if out:
            log(f"{INFO} netsh interfaces (ativo/estado):")
            for line in out.splitlines():
                if line.strip():
                    log(f"       {line}")
        out = run_cmd(["ipconfig", "/all"])
        if out:
            current = {}
            for line in out.splitlines():
                s = line.strip()
                if not s:
                    if current:
                        ifaces.append(current)
                        current = {}
                    continue
                if not s.startswith(" ") and s.endswith(":"):
                    if current:
                        ifaces.append(current)
                    current = {"name": s.rstrip(":")}
                elif ":" in s and current:
                    k, _, v = s.partition(":")
                    current[k.strip()] = v.strip()
            if current:
                ifaces.append(current)
            for ifc in ifaces:
                if any(k for k in ifc if "IPv4" in k or "Gateway" in k or "DHCP" in k):
                    name = ifc.get("name", "?")
                    def find(keywords):
                        for k, v in ifc.items():
                            if all(w.lower() in k.lower() for w in keywords):
                                return v
                        return "-"
                    ipv4 = find(["IPv4"])
                    mask = find(["Mascara"]) if find(["Mascara"]) != "-" else find(["Mask"])
                    gw = find(["Gateway", "Padrao"]) if find(["Gateway", "Padrao"]) != "-" else find(["Gateway", "Default"])
                    dhcp = find(["DHCP", "Ativado"]) if find(["DHCP", "Ativado"]) != "-" else find(["DHCP", "Enabled"])
                    dns = find(["Servidores DNS"]) if find(["Servidores DNS"]) != "-" else find(["DNS Servers"])
                    log(f"{INFO} Adaptador: {name}")
                    log(f"       IPv4={ipv4}  Mascara={mask}")
                    log(f"       Gateway={gw}  DHCP={dhcp}")
                    log(f"       DNS={dns}")
    else:
        out = run_cmd(["ip", "-br", "addr"]) or run_cmd(["ifconfig", "-a"])
        if out:
            log(f"{INFO} interfaces:")
            log("\n".join(f"       {ln}" for ln in out.splitlines()))
    return ifaces


# ============================================================
# CAMADA 3: ICMP (ping) + MTU
# ============================================================
def ping_win(host, count=2, timeout_ms=2000, size=None):
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms)]
    if size is not None:
        cmd += ["-l", str(size), "-f"]
    cmd += [host]
    return run_cmd(cmd, timeout=10)


def ping_unix(host, count=2, timeout_s=2, size=None):
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s)]
    if size is not None:
        cmd += ["-M", "do", "-s", str(size)]
    cmd += [host]
    return run_cmd(cmd, timeout=10)


def parse_ping(out, host):
    if not out:
        return None
    # percentual de perda
    loss = None
    time_avg = None
    if "perdidos" in out.lower() or "loss" in out.lower():
        for line in out.splitlines():
            low = line.lower()
            if "perdidos" in low or "loss" in low:
                if "(" in line:
                    try:
                        loss = int(line.split("(")[-1].split("%")[0])
                    except ValueError:
                        loss = None
                break
    if "medio" in out.lower() or "avg" in out.lower() or "average" in out.lower():
        for line in out.splitlines():
            low = line.lower()
            if "medio" in low or "avg" in low or "average" in low:
                for tok in line.replace(",", " ").replace("=", " ").replace("ms", "").split():
                    try:
                        time_avg = float(tok)
                        break
                    except ValueError:
                        pass
    # Fallback: media de tempo/ms em linhas individuais
    if time_avg is None:
        times = []
        for line in out.splitlines():
            low = line.lower()
            if "tempo=" in low or "time=" in low or "tempo<" in low:
                for tok in low.replace("<", "=").split():
                    if tok.startswith("tempo=") or tok.startswith("time="):
                        try:
                            times.append(float(tok.split("=")[1].replace("ms", "")))
                        except ValueError:
                            pass
        if times:
            time_avg = sum(times) / len(times)
    return {"loss": loss, "avg_ms": time_avg, "raw": out}


def test_ping(log, host_label, host, count=2):
    if host == "__GATEWAY__":
        host = GATEWAY or "0.0.0.0"
    if not host or host in ("0.0.0.0", "::"):
        log(f"{WARN} {host_label} ({host})  -> SKIP (nao detectado)")
        return {"target": host_label, "host": host, "status": "skip"}
    fn = ping_win if IS_WINDOWS else ping_unix
    out = fn(host, count=count)
    r = parse_ping(out, host)
    if not r:
        log(f"{FAIL} {host_label} ({host})  -> SEM RESPOSTA")
        return {"target": host_label, "host": host, "status": "fail"}
    loss, avg = r["loss"], r["avg_ms"]
    if loss is None or loss >= 100:
        log(f"{FAIL} {host_label} ({host})  -> 100% perda")
        return {"target": host_label, "host": host, "status": "fail", "loss": loss}
    status = "ok" if (loss or 0) < 50 else "warn"
    tag = OK if status == "ok" else WARN
    avg_str = f"{avg:.1f}ms" if avg is not None else "?"
    log(f"{tag} {host_label} ({host})  -> perda={loss or 0}%  latencia={avg_str}")
    return {"target": host_label, "host": host, "status": status,
            "loss": loss, "avg_ms": avg}


def test_mtu(log, host="1.1.1.1"):
    """Determina MTU aproximado com ping DF bit setado."""
    banner(log, "CAMADA 2-3: DESCOBERTA DE MTU (Path MTU Discovery)")
    fn = ping_win if IS_WINDOWS else ping_unix
    lo, hi = 1400, 1500
    best = 1400
    try:
        while lo <= hi:
            mid = (lo + hi) // 2
            size = mid - 28
            out = fn(host, count=1, size=size, timeout_ms=2000)
            ok = out and (
                ("tempo=" in out.lower() or "time=" in out.lower()) and
                "fragment" not in out.lower() and "Frag" not in out and
                "excedeu" not in out.lower() and "exceed" not in out.lower()
            )
            if ok:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        log(f"{OK} MTU estimado para {host}: {best} bytes"
            + ("  (abaixo de 1500 - possivel VPN/PPPoE)" if best < 1490 else ""))
        if best < 1400:
            log(f"{WARN} MTU muito baixo. Considere ajustar MTU do adaptador para 1400.")
        return {"best_mtu": best}
    except Exception as e:
        log(f"{FAIL} Teste de MTU indisponivel: {e}")
        return {"best_mtu": None}


# ============================================================
# CAMADA 4: TCP sockets (handshake) + UDP DNS
# ============================================================
def tcp_connect(host, port, timeout=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        dt = (time.perf_counter() - t0) * 1000
        s.close()
        return True, dt
    except Exception as e:
        s.close()
        return False, str(e)


def test_port_targets(log, host):
    banner(log, f"CAMADA 4: CONEXAO TCP PARA {host} (handshake SYN/ACK)")
    results = []
    for label, port in COMMON_PORTS:
        ok, info = tcp_connect(host, port)
        if ok:
            log(f"{OK} {label:20s} porta {port:4d}  -> ABERTA  ({info:.1f}ms)")
            results.append({"port": port, "status": "open", "ms": info})
        else:
            tag = WARN if "refused" in str(info).lower() or "reset" in str(info).lower() else FAIL
            log(f"{tag} {label:20s} porta {port:4d}  -> FALHOU ({info})")
            results.append({"port": port, "status": "closed/filtered", "error": str(info)})
    return results


# ============================================================
# CAMADA 5-7: DNS + HTTP/HTTPS + proxy + hosts
# ============================================================
def dns_query_py(domain, nameserver=None, timeout=3):
    """Resolve um dominio usando UDP direto se nameserver for dado, senao getaddrinfo."""
    t0 = time.perf_counter()
    if nameserver is None:
        try:
            res = socket.getaddrinfo(domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ips = list({r[4][0] for r in res})
            return ips, (time.perf_counter() - t0) * 1000, None
        except Exception as e:
            return None, (time.perf_counter() - t0) * 1000, str(e)
    # UDP DNS query direto (RFC 1035)
    try:
        import random
        txn = random.randint(0, 0xFFFF)
        query = struct.pack("!HHHHHH", txn, 0x0100, 1, 0, 0, 0)
        for label in domain.split("."):
            query += bytes([len(label)]) + label.encode("ascii")
        query += b"\x00"
        query += struct.pack("!HH", 1, 1)  # A record, IN class
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (nameserver, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) < 12 or struct.unpack("!H", data[:2])[0] != txn:
            return None, (time.perf_counter() - t0) * 1000, "resposta invalida"
        flags = struct.unpack("!H", data[2:4])[0]
        if flags & 0x000F:  # RCODE != 0
            rcode = flags & 0x000F
            errors = {1: "Format error", 2: "Server failure", 3: "NXDOMAIN (nao existe)",
                      4: "Not implemented", 5: "Refused"}
            return None, (time.perf_counter() - t0) * 1000, f"RCODE {rcode}: {errors.get(rcode, '?')}"
        qdcount, ancount = struct.unpack("!HH", data[4:8])
        idx = 12
        for _ in range(qdcount):
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 5
        ips = []
        for _ in range(ancount):
            if idx + 2 > len(data):
                break
            if data[idx] & 0xC0 == 0xC0:
                idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1
            if idx + 10 > len(data):
                break
            rtype, rclass, rttl, rdlen = struct.unpack("!HHIH", data[idx:idx+10])
            idx += 10
            rdata = data[idx:idx+rdlen]
            idx += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in rdata))
        return ips or None, (time.perf_counter() - t0) * 1000, None
    except Exception as e:
        return None, (time.perf_counter() - t0) * 1000, str(e)


def test_dns_servers(log, domain="google.com.br"):
    banner(log, f"CAMADA 5-7: RESOLUCAO DNS comparativa ({domain})")
    results = {}
    for name, ns in DNS_SERVERS:
        ips, ms, err = dns_query_py(domain, ns)
        if ips:
            ip_str = ", ".join(ips[:3]) + ("..." if len(ips) > 3 else "")
            log(f"{OK} {name:20s}  -> {ip_str}  ({ms:.0f}ms)")
            results[name] = {"status": "ok", "ips": ips, "ms": ms, "server": ns}
        else:
            log(f"{FAIL} {name:20s}  -> FALHOU: {err or 'sem ip'}  ({ms:.0f}ms)")
            results[name] = {"status": "fail", "error": err, "ms": ms, "server": ns}
    # Comparar consistencia (soh alerta se DNS do sistema for completamente disjunto)
    oks = {n: r for n, r in results.items() if r["status"] == "ok"}
    if len(oks) >= 2:
        sys_ips = set()
        ext_ips = set()
        for n, r in oks.items():
            if "Sistema" in n or "padrao" in n:
                sys_ips.update(r["ips"])
            else:
                ext_ips.update(r["ips"])
        if sys_ips and ext_ips and not (sys_ips & ext_ips):
            log(f"{WARN} ATENCAO: DNS do sistema retornou IPs distintos dos demais servidores (possivel filtro/hijack).")
            for n, r in oks.items():
                log(f"       {n}: {sorted(r['ips'])}")
        else:
            ip_sets = [tuple(sorted(r["ips"])) for r in oks.values()]
            if len(set(ip_sets)) > 1:
                log(f"{INFO} Observacao: servidores DNS retornaram IPs diferentes (comum por CDN/Anycast)")
    return results


def test_multiple_domains(log):
    banner(log, "CAMADA 5-7: RESOLUCAO de multiplos dominios (DNS padrao)")
    results = {}
    for d in TEST_DOMAINS:
        ips, ms, err = dns_query_py(d)
        if ips:
            log(f"{OK} {d:30s}  -> {ips[0]}  ({ms:.0f}ms)")
            results[d] = {"status": "ok", "ips": ips, "ms": ms}
        else:
            err_str = err or "N/A"
            # categorizar erro
            if err and ("NXDOMAIN" in err or "nome" in err.lower() or "getaddrinfo" in err and "fail" in err.lower()):
                log(f"{FAIL} {d:30s}  -> NXDOMAIN / dominio nao existe? ({err_str})")
                status = "nxdomain"
            elif err and ("timeout" in err.lower() or "timed out" in err.lower()):
                log(f"{FAIL} {d:30s}  -> TIMEOUT do DNS ({err_str})")
                status = "timeout"
            else:
                log(f"{FAIL} {d:30s}  -> FALHA: {err_str}")
                status = "fail"
            results[d] = {"status": status, "error": err, "ms": ms}
    return results


def check_hosts_file(log):
    banner(log, "CAMADA 5-7: ARQUIVO HOSTS (bloqueios/entradas estaticas)")
    p = Path(TEST_HOSTS_FILE)
    if not p.exists():
        log(f"{WARN} Arquivo hosts nao encontrado em {p}")
        return {"exists": False}
    try:
        content = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        log(f"{FAIL} Nao foi possivel ler hosts: {e}")
        return {"exists": True, "error": str(e)}
    lines = content.splitlines()
    entries = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        s = s.split("#", 1)[0].strip()
        parts = s.split()
        if len(parts) >= 2:
            entries.append((parts[0], " ".join(parts[1:])))
    log(f"{INFO} Total de entradas ativas no hosts: {len(entries)}")
    suspicious = [e for e in entries if e[1].lower() not in ("localhost", "localhost.localdomain",
                                                            "localhost6", "localhost6.localdomain6")
                  and e[0] not in ("127.0.0.1", "::1", "255.255.255.255", "0.0.0.0")]
    if suspicious:
        log(f"{WARN} Entradas NAO padrao encontradas (podem causar NXDOMAIN falsos):")
        for ip, host in suspicious:
            log(f"       {ip:20s}  {host}")
    else:
        log(f"{OK} Arquivo hosts limpo, sem entradas suspeitas.")
    return {"exists": True, "total": len(entries), "suspicious": suspicious}


def check_proxy_settings(log):
    banner(log, "CAMADA 5-7: CONFIGURACOES DE PROXY (sistema/variaveis)")
    info = {}
    # Variaveis de ambiente
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy"):
        val = os.environ.get(v)
        if val:
            log(f"{WARN} Variavel {v} = {val}")
            info[v] = val
    # Windows reg
    if IS_WINDOWS:
        out = run_cmd(["reg", "query",
                       r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                       "/v", "ProxyEnable"])
        if out and "0x1" in out:
            log(f"{WARN} Proxy do Windows ESTA ATIVADO (ProxyEnable=1)")
            info["win_proxy_enable"] = 1
            for val_name in ("ProxyServer", "AutoConfigURL"):
                out2 = run_cmd(["reg", "query",
                               r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                               "/v", val_name])
                if out2:
                    for ln in out2.splitlines():
                        if val_name in ln:
                            log(f"       {ln.strip()}")
                            info[val_name] = ln.strip()
        elif out and "0x0" in out:
            log(f"{OK} Proxy do Windows desativado.")
            info["win_proxy_enable"] = 0
        else:
            log(f"{INFO} Nao foi possivel ler reg de proxy.")
    return info


def test_http_sites(log):
    banner(log, "CAMADA 7: REQUISICOES HTTP/HTTPS (simula navegador)")
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                             "AppleWebKit/537.36 net_troubleshoot/1.0"}
    for url, expected in HTTP_TESTS:
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                size = len(resp.read(512))
                ms = (time.perf_counter() - t0) * 1000
                ok = (status == expected) or (expected in (200, 204) and 200 <= status < 400)
                tag = OK if ok else WARN
                log(f"{tag} {url:55s}  -> HTTP {status}  ({ms:.0f}ms, {size}B lidos)"
                    + ("   esperava=" + str(expected) if not ok else ""))
                results.append({"url": url, "status": "ok" if ok else "unexpected",
                                "http": status, "ms": ms})
        except urllib.error.HTTPError as e:
            ms = (time.perf_counter() - t0) * 1000
            tag = FAIL if e.code >= 500 else WARN
            log(f"{tag} {url:55s}  -> HTTP ERROR {e.code}  ({ms:.0f}ms)")
            results.append({"url": url, "status": "http_error", "http": e.code, "ms": ms})
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000
            estr = str(e)
            if "reset" in estr.lower():
                tag = FAIL
                detail = "CONNECTION RESET (possivel firewall/MTU)"
            elif "time" in estr.lower():
                tag = FAIL
                detail = "TIMEOUT (sem retorno)"
            elif "cert" in estr.lower() or "SSL" in estr:
                tag = WARN
                detail = "ERRO SSL/certificado"
            elif "nxdomain" in estr.lower() or "getaddrinfo" in estr.lower():
                tag = FAIL
                detail = "DNS FAIL / NXDOMAIN"
            elif "refused" in estr.lower():
                tag = FAIL
                detail = "CONNECTION REFUSED"
            else:
                tag = FAIL
                detail = estr[:80]
            log(f"{tag} {url:55s}  -> {detail}  ({ms:.0f}ms)")
            results.append({"url": url, "status": "error", "error": detail, "ms": ms})
    return results


def test_direct_ip_http(log):
    """Testa HTTP/HTTPS por IP diretamente, para isolar falha DNS vs falha IP."""
    banner(log, "CAMADA 7: HTTP DIRETO POR IP (isola DNS de rede)")
    tests = [
        ("Cloudflare (direto por IP)", "http://1.1.1.1/", 301),
        ("Google DNS API (direto)",   "http://8.8.8.8/", 301),
    ]
    results = []
    headers = {"User-Agent": "Mozilla/5.0 net_troubleshoot/1.0", "Host": "example.com"}
    for label, url, _expected in tests:
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": headers["User-Agent"]})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ms = (time.perf_counter() - t0) * 1000
                log(f"{OK} {label:30s}  -> HTTP {resp.status}  ({ms:.0f}ms)")
                results.append({"label": label, "status": "ok", "http": resp.status, "ms": ms})
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000
            detail = str(e)[:100]
            log(f"{FAIL} {label:30s}  -> FALHA: {detail}  ({ms:.0f}ms)")
            results.append({"label": label, "status": "fail", "error": str(e), "ms": ms})
    return results


def test_arp_and_nd(log):
    banner(log, "CAMADA 2: TABELA ARP (verifica gateway duplicado/ARP spoofing)")
    out = run_cmd(["arp", "-a"]) if IS_WINDOWS else run_cmd(["ip", "neigh"]) or run_cmd(["arp", "-n"])
    if not out:
        log(f"{WARN} Nao foi possivel obter tabela ARP.")
        return None
    log(f"{INFO} Tabela ARP:")
    for ln in out.splitlines():
        log(f"       {ln}")
    # detectar duplicatas (mesmo MAC em IPs diferentes nao eh bom a menos q seja bonding)
    mac_to_ips = {}
    for ln in out.splitlines():
        parts = ln.split()
        for p in parts:
            if p.count(":") == 5 or p.count("-") == 5:
                mac = p.lower().replace("-", ":")
                for q in parts:
                    if "." in q and q.count(".") == 3 and ":" not in q:
                        if q[0].isdigit():
                            mac_to_ips.setdefault(mac, set()).add(q)
                break
    multi = {m: ips for m, ips in mac_to_ips.items() if len(ips) > 1 and m != "ff:ff:ff:ff:ff:ff"}
    if multi:
        log(f"{WARN} Multiplos IPs respondendo para o mesmo MAC (possivel ARP spoof ou VIP):")
        for m, ips in multi.items():
            log(f"       MAC {m}  -> IPs: {', '.join(ips)}")
    else:
        log(f"{OK} Sem duplicatas suspeitas na tabela ARP.")
    return out


# ============================================================
# DIAGNOSTICO FINAL + SUGESTOES
# ============================================================
def build_diagnosis(log, results):
    banner(log, "DIAGNOSTICO E ANALISE FINAL")
    issues = []
    fixes = []

    # Recupera resultados
    ping_gw = next((r for r in results["pings"] if "Gateway" in r.get("target", "")), None)
    ping_ext = [r for r in results["pings"] if r.get("host") in ("1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")]

    # Regra 1: ping gateway falha => problema local (wi-fi, cabo, switch, IP invalido)
    if ping_gw and ping_gw.get("status") == "fail":
        issues.append("Nao ha resposta ICMP do GATEWAY padrão.")
        fixes.append(">>> Problema LOCAL: Verifique cabo/rede wi-fi, reinicie roteador/switch.")
        fixes.append("    Confirme se o IP do adaptador na mesma sub-rede do gateway (ver camada 2 acima).")
        fixes.append("    Teste 'ipconfig /renew' (Windows) se DHCP, ou confira IP estatico.")

    # Regra 2: ping gw ok mas 8.8.8.8 falha => sem saida para internet (provedor, regra firewall, NAT)
    ext_fail = [r for r in ping_ext if r.get("status") == "fail"]
    ext_ok = [r for r in ping_ext if r.get("status") == "ok"]
    if ping_gw and ping_gw.get("status") == "ok" and len(ext_fail) >= 2 and len(ext_ok) == 0:
        issues.append("Gateway acessivel mas IPs publicos (1.1.1.1, 8.8.8.8) nao respondem.")
        fixes.append(">>> Sem ROTA para a INTERNET. Verifique se o provedor esta OK ou regras de firewall/NAT")
        fixes.append("    no roteador. Confira a tabela de rotas: 'route print' ou 'ip route'.")

    # Regra 3: DNS padrao falha mas Google/Cloudflare resolvem => DNS do ISP ruim/infectado
    dns = results["dns_servers"]
    sysdns = dns.get("Sistema (padrao)", {})
    ext_dns_ok = any(dns.get(n, {}).get("status") == "ok" for n in ("Google DNS", "Cloudflare", "Quad9"))
    if sysdns.get("status") != "ok" and ext_dns_ok:
        issues.append("DNS do sistema (ISP/roteador) falha, mas DNS publicos resolvem bem.")
        fixes.append(">>> Configure DNS PUBLICOS no adaptador (IPv4):")
        fixes.append("    Primario: 8.8.8.8  Secundario: 1.1.1.1  (ou 9.9.9.9)")
        fixes.append("    Windows: painel de rede -> Propriedades IPv4 -> 'Usar os seguintes DNS'")
        fixes.append("    Apos mudar, execute:  ipconfig /flushdns")
        fixes.append("    Isso resolve a maioria dos casos de dns_probe_finished_nxdomain!")

    # Regra 4: DNS inconsistente entre servidores
    oks = {n: r for n, r in dns.items() if r.get("status") == "ok"}
    if len(oks) >= 2:
        sets = [tuple(sorted(r.get("ips", []))) for r in oks.values()]
        if len(set(sets)) > 1:
            sys_ips = set()
            externos_ips = set()
            for n, r in oks.items():
                if "Sistema" in n or "padrao" in n:
                    sys_ips.update(r.get("ips", []))
                else:
                    externos_ips.update(r.get("ips", []))
            # Se houver intersecao vazia E o DNS do sistema nao compartilhar
            # NENHUM IP com os outros => forte suspeita
            if sys_ips and externos_ips and not (sys_ips & externos_ips):
                issues.append("DNS do sistema retorna IPs COMPLETAMENTE diferentes dos DNS publicos (possivel hijack/filtering).")
                fixes.append(">>> CUIDADO: sua rede pode estar usando DNS com filtro (corporativo, pai, ou malware).")
                fixes.append("    Se nao for intencional, configure manualmente 8.8.8.8 e 1.1.1.1 (veja regra 3).")

    # Regra 5: NXDOMAIN em todos os dominios (exceto aquele que realmente nao existe)
    domains = results["domains"]
    if domains:
        real_failures = [(k, v) for k, v in domains.items() if k.lower() not in ("lan.rnp.br",) and v.get("status") == "nxdomain"]
        valid_domains = [k for k in domains if k.lower() not in ("lan.rnp.br",)]
        all_nx = len(real_failures) == len(valid_domains) and valid_domains
        if all_nx:
            issues.append("Todos os dominios conhecidos retornaram NXDOMAIN (DNS diz que nao existem).")
            fixes.append(">>> DNS do sistema parece INVALIDO ou envenenado. Aplique a troca de DNS (regra 3).")
            fixes.append("    Se persistir, reinicie o modem/roteador. Verifique data/hora do SO.")

    # Regra 6: HTTP por IP ok mas HTTP por dominio falha => DNS isolado
    dir_ok = any(r.get("status") == "ok" for r in results["direct_ip"])
    any_http_dns_fail = any(r.get("status") == "error" and "DNS" in r.get("error", "")
                            for r in results["http"])
    if dir_ok and any_http_dns_fail:
        issues.append("Conexao por IP funciona, mas por dominio falha (DNS isolado).")
        fixes.append(">>> Conclusao: a REDE funciona, apenas o DNS esta quebrado. Trocar os DNS (regra 3)")
        fixes.append("    devera resolver. Se nao, desative VPNs, proxies ou clientes de seguranca.")

    # Regra 7: HTTP por IP tambem falha => camada IP/rota/MTU
    dir_all_fail = all(r.get("status") != "ok" for r in results["direct_ip"]) if results["direct_ip"] else False
    if dir_all_fail and ext_ok:
        issues.append("Ping em IPs publicos OK, mas HTTP/HTTPS por IP falha.")
        fixes.append(">>> Provavel MTU incorreto ou firewall bloqueando portas 80/443.")
        fixes.append("    Teste abaixar MTU do adaptador para 1400. Windows:")
        fixes.append("    netsh interface ipv4 set subinterface \"Wi-Fi\" mtu=1400 store=persistent")
        fixes.append("    Ou, se cabo: netsh interface ipv4 set subinterface \"Ethernet\" mtu=1400 store=persistent")
        fixes.append("    Verifique tambem se ha proxy transparente ou antivírus interceptando HTTPS.")

    # Regra 8: Connection reset apos alguns bytes
    resets = [r for r in results["http"] if r.get("status") == "error" and "RESET" in r.get("error", "").upper()]
    if resets:
        issues.append(f"Ocorreram {len(resets)} CONNECTION RESET em HTTP/HTTPS.")
        fixes.append(">>> Connection reset tipicamente ocorre por: MTU errado, firewall/IDS, proxy transparente,")
        fixes.append("    antivirus com inspecao HTTPS, ou NAT state table corrompida no roteador.")
        fixes.append("    Tente ajustar MTU (regra 7) e, se possivel, reiniciar o roteador.")

    # Regra 9: Proxy ativado indevidamente
    proxy = results["proxy"]
    env_proxy = any("PROXY" in k.upper() and proxy.get(k) for k in proxy.keys())
    win_proxy_on = proxy.get("win_proxy_enable") == 1
    if win_proxy_on or env_proxy:
        issues.append("Proxy de sistema esta ATIVADO.")
        fixes.append(">>> Verifique se voce realmente precisa deste proxy. Desative temporariamente:")
        fixes.append("    Windows: Configuracoes -> Rede e Internet -> Proxy -> Desativar 'Detectar automaticamente'")
        fixes.append("    e 'Usar servidor proxy'.")

    # Regra 10: Hosts suspeito
    h = results["hosts"]
    if isinstance(h, dict) and h.get("suspicious"):
        issues.append(f"{len(h['suspicious'])} entrada(s) suspeita(s) no arquivo HOSTS.")
        fixes.append(">>> Edite o arquivo hosts e remova as entradas suspeitas listadas acima.")

    if not issues:
        log(f"{OK} NENHUM problema estrutural detectado — rede operando normalmente.")
        log(f"{INFO} Se voce ainda assim tem intermitencia, o problema pode ser no:")
        log("     * Navegador (extensoes, cache DNS do browser, DoH)")
        log("     * Antivirus / firewall de terceiros")
        log("     * Conexao Wi-Fi instavel (mude para cabo para testar)")
        log("     * Problema intermitente no ISP (execute este script varias vezes)")
        return [], []

    log(f"{WARN}  PROBLEMAS ENCONTRADOS: {len(issues)}")
    for i, iss in enumerate(issues, 1):
        log(f"  {i:2d}. {iss}")
    log(f"{INFO}")
    log(f"{INFO} SUGESTOES DE CORRECAO (por ordem de probabilidade):")
    for fix in fixes:
        log(f"  {fix}")

    return issues, fixes


# ============================================================
# FUNCOES PARA COMPILACAO .EXE E ABERTURA AUTOMATICA DE LOG
# ============================================================
def get_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def open_folder_in_explorer(path):
    if not IS_WINDOWS:
        return False
    try:
        os.startfile(str(path))  # noqa: B301 - Windows-only
        return True
    except Exception:
        return False


def open_in_notepad(path):
    if not IS_WINDOWS:
        return False
    try:
        import subprocess as _sp
        _sp.Popen(["notepad.exe", str(path)],
                  creationflags=_sp.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return True
    except Exception:
        return False


def pause_before_exit_if_exe():
    """Quando rodando como .exe, evita que a janela feche imediatamente apos terminar."""
    if not getattr(sys, "frozen", False):
        return
    try:
        print()
        input("Pressione ENTER para fechar esta janela...")
    except EOFError:
        pass


# ============================================================
# FUNCAO PRINCIPAL
# ============================================================
def main():
    ap = argparse.ArgumentParser(description="Diagnostico completo de conectividade de rede")
    ap.add_argument("--host", help="Host adicional de rede local para testar (ex: servidor.local, 192.168.1.50)")
    ap.add_argument("--json", help="Caminho para salvar relatorio em JSON")
    ap.add_argument("--log", action="store_true", help="Salva log texto em arquivo com data/hora")
    ap.add_argument("--no-open", action="store_true", help="Nao abre a pasta de logs / Notepad ao final (para .exe)")
    args = ap.parse_args()

    base_dir = get_base_dir()
    logs_dir = base_dir / "logs"
    try:
        logs_dir.mkdir(exist_ok=True, parents=True)
    except Exception:
        logs_dir = base_dir

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    is_exe = getattr(sys, "frozen", False)
    # Sempre gera log se for .exe (usuário pediu abertura automática)
    log_was_requested = args.log or is_exe
    log_path = str(logs_dir / f"net_troubleshoot_{ts}.log") if log_was_requested else None

    json_path = None
    if args.json:
        json_path = args.json
    elif is_exe:
        json_path = str(logs_dir / f"net_troubleshoot_{ts}.json")

    log = Logger(log_path)

    print(BANNER)
    log(f"Iniciado em: {dt.datetime.now().isoformat()}  |  Host: {socket.gethostname()}"
        f"  |  SO: {platform.platform()}")
    log(f"{INFO} Diretorio base: {base_dir}")
    log(f"{INFO} Diretorio de logs: {logs_dir}" + (f"  (log em: {log_path})" if log_path else ""))

    # Fase 0 - detectar gateway
    global GATEWAY
    GATEWAY = detect_gateway_windows(log) if IS_WINDOWS else detect_gateway_unix(log)
    log(f"{INFO} Gateway detectado: {GATEWAY or 'NAO ENCONTRADO'}")

    results = {}

    # Camada 1-2
    banner(log, "CAMADA 1-2: ADAPTADORES DE REDE, IP, MASCARA, GATEWAY, DHCP")
    results["interfaces"] = list_interfaces(log)

    # Tabela ARP
    results["arp"] = test_arp_and_nd(log)

    # Camada 3 - pings
    banner(log, "CAMADA 3: PING ICMP (gateway e servicos publicos)")
    ping_targets = list(PING_TARGETS)
    if args.host:
        ping_targets.insert(1, (f"Host custom ({args.host})", args.host))
    results["pings"] = [test_ping(log, lbl, h) for lbl, h in ping_targets]

    # MTU
    results["mtu"] = test_mtu(log)

    # Camada 4 - TCP contra host
    banner(log, "CAMADA 4: CONEXAO TCP CONTRA GATEWAY (verifica se roteador responde)")
    if GATEWAY:
        test_port_targets(log, GATEWAY)
    if args.host:
        results["tcp_custom"] = test_port_targets(log, args.host)

    # Camada 5 - DNS
    results["dns_servers"] = test_dns_servers(log)
    results["domains"] = test_multiple_domains(log)

    # Hosts
    results["hosts"] = check_hosts_file(log)

    # Proxy
    results["proxy"] = check_proxy_settings(log)

    # Camada 7 - HTTP
    results["direct_ip"] = test_direct_ip_http(log)
    results["http"] = test_http_sites(log)

    # Diagnostico
    issues, fixes = build_diagnosis(log, results)

    # Salva JSON
    json_saved = None
    if json_path:
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp": ts,
                    "gateway": GATEWAY,
                    "issues": issues,
                    "fixes": fixes,
                    "results": results,
                }, f, ensure_ascii=False, indent=2, default=str)
            log(f"{INFO} Relatorio JSON salvo em: {json_path}")
            json_saved = json_path
        except Exception as e:
            log(f"{FAIL} Erro ao salvar JSON: {e}")

    log_saved = log.save()
    if log_saved:
        log(f"{INFO} Log completo salvo em: {log_path}")

    log(f"\n{INFO} Concluido. Total de problemas: {len(issues)}")

    # Acao final do .exe: abrir pasta de logs + log no notepad
    if (log_saved or json_saved) and not args.no_open and is_exe:
        log(f"\n{INFO} Abrindo diretorio de logs e Notepad com o relatorio...")
        time.sleep(1.0)
        try:
            if log_saved:
                open_in_notepad(log_path)
            time.sleep(0.5)
            open_folder_in_explorer(logs_dir)
        except Exception as e:
            log(f"{WARN} Nao foi possivel abrir Notepad/Explorer: {e}")


if __name__ == "__main__":
    GATEWAY = None
    try:
        main()
        pause_before_exit_if_exe()
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuario.")
        pause_before_exit_if_exe()
        sys.exit(130)
    except Exception as _unhandled:
        try:
            print(f"\n\nERRO NAO TRATADO: {_unhandled}")
            import traceback
            traceback.print_exc()
        finally:
            pause_before_exit_if_exe()
            sys.exit(1)
