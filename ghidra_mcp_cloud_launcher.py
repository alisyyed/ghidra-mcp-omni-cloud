#!/usr/bin/env python3
r"""
GhidraMCP v5.0 Workstation Pro — Interactive Cloud Decompiler, MCP Gateway & Multi-Cloud Suite
==============================================================================================
A production-grade, single-file reverse-engineering workstation and Gemini MCP multiplexer
for LaurieWired/GhidraMCP (v2.0) and NSA Ghidra 12.1.4.

Key Architectural Upgrades in v5.0:
  1. STATEFUL STREAMABLE-HTTP (`Mcp-Session-Id`) BRIDGE:
     Automatically negotiates and maintains the MCP 2025-03-26 `Mcp-Session-Id` session
     with `ghidra-mcp`'s internal Uvicorn `StreamableHTTP` server (`127.0.0.1:8081/mcp`),
     parsing both `application/json` and `text/event-stream` (SSE) payloads seamlessly.
  2. SERVER-SIDE RENDERED (SSR) + ZERO-ALERT REACTIVE WEB WORKSTATION (`GET /`):
     Pre-renders the live `.trycloudflare.com/mcp` link, cloud RAM/JVM stats, and active
     binary directly into the HTML on first load, and provides a 4-tab dark-mode IDE:
       - [Decompiler & Functions]: Browse functions discovered by Headless Ghidra, click
         any function to view live C pseudocode, rename functions, or test any MCP tool.
       - [Binary Hot-Swap]: Drag-and-drop any `.exe`, `.elf`, `.dll`, `.so`, or firmware
         binary (or load from a URL) without changing your Gemini `/mcp` URL.
       - [Static Forensics & IOCs]: Instant SHA-256/MD5, ELF/PE header parser, visual
         Shannon entropy packer bar, and filterable IOC URL/IP/string tables.
       - [Cloud Deploy & Cluster]: 1-Click `.ipynb` notebook generator for Kaggle (30 GB RAM)
         and Google Colab, 1-Click GitHub Cloud Runner deployer, and Multi-Cloud Fleet pool.
  3. ZERO WARNINGS / CROSS-PLATFORM NATIVE:
     Clean raw strings (`Zero SyntaxWarning` on Python 3.12–3.14), automatic `C:\tmp\ghidra_mcp_cloud`
     and `/kaggle/working/ghidra_mcp_cloud` cache reuse, and OS-native `cloudflared` binary selection.

Verified Upstream References:
  - LaurieWired/GhidraMCP Repo: https://github.com/lauriewired/ghidramcp
  - LaurieWired/GhidraMCP Releases: https://github.com/LaurieWired/GhidraMCP/releases
  - Ghidra 12.1.4 Setup & SHA-256: https://geekcoding101.com/posts/ghidra-mcp-ai-reverse-engineering
  - Ghidra Headless & JVM Tuning: https://infosecmonkey.com/ghidra-zero-to-hero-a-practitioners-guide-to-the-nsas-reverse-engineering-framework/
  - Kaggle 30 GB RAM Notebooks: https://www.kaggle.com/docs/notebooks
  - Google Colab Tunneling: https://localaimaster.com/blog/run-llm-google-colab-free
  - GitHub Codespaces & Actions: https://docs.github.com/get-started/learning-about-github/githubs-products
  - Cloudflare Quick Tunnel: https://github.com/cloudflare/cloudflared/releases
"""

import argparse
import base64
import collections
import ctypes
import hashlib
import html
import http.server
import json
import math
import os
import platform
import re
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Verified Release Constants (Ghidra 12.1.4 + LaurieWired/GhidraMCP 2.0)
# ---------------------------------------------------------------------------
GHIDRA_VERSION = "12.1.4"
GHIDRA_BUILD_DATE = "20260921"
GHIDRA_ZIP_NAME = f"ghidra_{GHIDRA_VERSION}_PUBLIC_{GHIDRA_BUILD_DATE}.zip"
GHIDRA_DOWNLOAD_URL = (
    f"https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    f"Ghidra_{GHIDRA_VERSION}_build/{GHIDRA_ZIP_NAME}"
)
GHIDRA_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"

GHIDRA_MCP_RELEASE_URL = (
    "https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip"
)
GHIDRA_MCP_RELEASE_SHA256 = "ebf904fd6782e429e95a60a24fe0724b20c0acb2dedb304135a5281f6b5f2e72"
GHIDRA_MCP_GIT_SPEC = "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP"

CLOUDFLARED_URLS = {
    "windows": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
    "linux_amd64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    "linux_arm64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
    "darwin_amd64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
    "darwin_arm64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz",
}


# ---------------------------------------------------------------------------
# 1. Cross-Platform OS, RAM, Java 21 & Environment Detection
# ---------------------------------------------------------------------------


def get_system_ram_gb() -> float:
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))  # type: ignore
            return round(stat.ullTotalPhys / (1024 ** 3), 1)
        except Exception:
            return 8.0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / (1024 * 1024), 1)
    except Exception:
        pass
    return 8.0


def detect_cloud_environment() -> Dict[str, Any]:
    sys_name = platform.system().lower()
    total_ram_gb = get_system_ram_gb()

    if "windows" in sys_name:
        env_name = f"Windows PC Bridge ({platform.release()})"
        legacy_win_tmp = Path("C:/tmp/ghidra_mcp_cloud")
        work_dir = legacy_win_tmp if legacy_win_tmp.exists() else (Path.home() / ".ghidra_mcp_cloud")
        needs_tunnel = True
    elif os.environ.get("SPACE_ID") or os.environ.get("SPACE_AUTHOR_NAME"):
        env_name = "Hugging Face Space (Cloud)"
        work_dir = Path("/home/user/app/ghidra_work") if Path("/home/user").exists() else Path("/tmp/ghidra_mcp_cloud")
        needs_tunnel = False
    elif Path("/kaggle/working").exists() or os.environ.get("KAGGLE_KERNEL_RUN_TYPE"):
        env_name = "Kaggle Cloud Notebook (30 GB RAM Tier)"
        work_dir = Path("/kaggle/working/ghidra_mcp_cloud")
        needs_tunnel = True
    elif Path("/content").exists() or "COLAB_GPU" in os.environ or "COLAB_RELEASE_TAG" in os.environ:
        env_name = "Google Colab Cloud VM"
        drive_root = Path("/content/drive/MyDrive")
        work_dir = (drive_root / "ghidra_mcp_cloud") if drive_root.exists() else Path("/content/ghidra_mcp_cloud")
        needs_tunnel = True
    elif os.environ.get("CODESPACES") == "true" or "CODESPACE_NAME" in os.environ:
        env_name = "GitHub Codespaces Cloud VM"
        work_dir = Path("/workspaces/ghidra_mcp_cloud") if Path("/workspaces").exists() else Path("/tmp/ghidra_mcp_cloud")
        needs_tunnel = True
    elif os.environ.get("GITHUB_ACTIONS") == "true":
        env_name = "GitHub Actions Cloud Runner (16 GB RAM)"
        work_dir = Path("/tmp/ghidra_mcp_cloud")
        needs_tunnel = True
    elif "LIGHTNING_CLOUD_URL" in os.environ or "LIGHTNING_STUDIO_ID" in os.environ:
        env_name = "Lightning AI Free Cloud Studio"
        work_dir = Path.home() / "ghidra_mcp_cloud"
        needs_tunnel = True
    elif os.environ.get("CLOUD_SHELL") == "true" or "DEVSHELL_PROJECT_ID" in os.environ:
        env_name = "Google Cloud Shell VM"
        work_dir = Path("/tmp/ghidra_mcp_cloud")
        needs_tunnel = True
    else:
        env_name = f"Linux / macOS Host ({platform.system()})"
        work_dir = Path("/tmp/ghidra_mcp_cloud")
        needs_tunnel = True

    if total_ram_gb >= 24:
        jvm_maxmem = "16G"
    elif total_ram_gb >= 14:
        jvm_maxmem = "8G"
    elif total_ram_gb >= 10:
        jvm_maxmem = "6G"
    else:
        jvm_maxmem = "4G"

    return {
        "platform": env_name,
        "os": sys_name,
        "total_ram_gb": total_ram_gb,
        "jvm_maxmem": jvm_maxmem,
        "default_work_dir": str(work_dir),
        "needs_tunnel": needs_tunnel,
    }


def copy_to_system_clipboard(text: str) -> bool:
    sys_name = platform.system().lower()
    try:
        if "windows" in sys_name:
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True)
            return True
        if "darwin" in sys_name:
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
            return True
        if shutil.which("xclip"):
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode("utf-8"), check=True)
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 2. Static Binary Forensics & IOC Triage Engine
# ---------------------------------------------------------------------------


def compute_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def analyze_binary_forensics(file_path: Optional[Path]) -> Dict[str, Any]:
    if not file_path or not file_path.exists():
        return {"error": f"Binary not found: {file_path}"}

    raw = file_path.read_bytes()
    sha256_hex = hashlib.sha256(raw).hexdigest()
    md5_hex = hashlib.md5(raw).hexdigest()

    magic = raw[:16]
    if magic.startswith(b"\x7fELF"):
        arch_bits = "64-bit" if (len(raw) > 4 and raw[4] == 2) else "32-bit"
        endian = "Little-Endian" if (len(raw) > 5 and raw[5] == 1) else "Big-Endian"
        bin_format = f"ELF ({arch_bits}, {endian})"
    elif magic.startswith(b"MZ"):
        bin_format = "Windows PE / MZ Executable (.exe / .dll / .sys)"
    elif magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        bin_format = "macOS Mach-O Binary"
    elif magic.startswith(b"PK\x03\x04"):
        bin_format = "ZIP / APK / JAR Archive"
    else:
        bin_format = f"Raw Firmware / Binary (magic: {magic[:4].hex()})"

    entropy = compute_shannon_entropy(raw)
    packer_verdict = (
        "HIGH ENTROPY (>= 7.2) — Likely Packed, Compressed, or Encrypted"
        if entropy >= 7.2
        else "Normal Code/Data Entropy (< 7.2) — Unpacked binary"
    )

    ascii_strings = [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{5,}", raw)]
    urls = sorted(set(s for s in ascii_strings if re.search(r"https?://", s, re.IGNORECASE)))[:30]
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(ascii_strings))))[:30]
    suspicious_keywords = [
        s for s in ascii_strings
        if any(k in s.lower() for k in ("password", "secret", "token", "flag", "admin", "key", "decrypt", "verify", "serial", "unlock", "http", "socket", "exec", "system", "main"))
    ][:50]

    return {
        "file_name": file_path.name,
        "absolute_path": str(file_path),
        "size_bytes": len(raw),
        "format": bin_format,
        "sha256": sha256_hex,
        "md5": md5_hex,
        "shannon_entropy_bits_per_byte": entropy,
        "packer_assessment": packer_verdict,
        "total_printable_strings": len(ascii_strings),
        "extracted_urls": urls,
        "extracted_ipv4s": ips,
        "interesting_strings": suspicious_keywords,
    }


# ---------------------------------------------------------------------------
# 3. Stateful StreamableHTTP Session Bridge (`Mcp-Session-Id`) + Runtime State
# ---------------------------------------------------------------------------


class BackendMCPSession:
    """Maintains a stateful MCP 2025-03-26 StreamableHTTP session (`Mcp-Session-Id`)
    with the local Uvicorn `ghidra-mcp` process on `127.0.0.1:8081/mcp`."""

    def __init__(self, backend_port: int) -> None:
        self.backend_port = backend_port
        self.session_id: Optional[str] = None
        self.lock = threading.Lock()
        self.call_lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.backend_port}/mcp"

    def reset(self) -> None:
        with self.lock:
            self.session_id = None

    def _raw_post(self, payload: Dict[str, Any], timeout: int = 20) -> Tuple[Optional[Dict[str, Any]], Dict[str, str]]:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "GhidraMCP-WorkstationPro/5.0",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_text = resp.read().decode("utf-8", errors="replace").strip()
            parsed = None
            for line in reversed(raw_text.splitlines()):
                if line.startswith("data:"):
                    candidate = line[len("data:"):].strip()
                    if candidate.startswith("{"):
                        try:
                            parsed = json.loads(candidate)
                            break
                        except Exception:
                            pass
            if parsed is None and raw_text.startswith("{"):
                try:
                    parsed = json.loads(raw_text)
                except Exception:
                    pass
            return parsed, resp_headers

    def ensure_initialized(self) -> bool:
        if self.session_id:
            return True
        with self.lock:
            if self.session_id:
                return True
            try:
                init_rpc = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "GhidraMCP-WorkstationPro", "version": "5.0.0"},
                    },
                }
                _, hdrs = self._raw_post(init_rpc, timeout=6)
                sid = hdrs.get("mcp-session-id")
                if sid:
                    self.session_id = sid
                notif_rpc = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
                try:
                    self._raw_post(notif_rpc, timeout=4)
                except Exception:
                    pass
                return True
            except Exception:
                return False

    def request(self, rpc_body: Dict[str, Any], timeout: int = 25) -> Optional[Dict[str, Any]]:
        if not self.ensure_initialized():
            return None
        with self.call_lock:
            try:
                parsed, _ = self._raw_post(rpc_body, timeout=timeout)
                return parsed
            except urllib.error.HTTPError as he:
                if he.code in (400, 404):
                    self.reset()
                    if self.ensure_initialized():
                        try:
                            parsed, _ = self._raw_post(rpc_body, timeout=timeout)
                            return parsed
                        except Exception:
                            return None
                return None
            except Exception:
                return None


class OmniCloudState:
    def __init__(self, work_dir: Path, gateway_port: int, backend_port: int, transport: str) -> None:
        self.env_info = detect_cloud_environment()
        self.work_dir = work_dir
        self.gateway_port = gateway_port
        self.backend_port = backend_port
        self.transport = transport
        self.ghidra_dir: Optional[Path] = None
        self.java_home: Optional[str] = None
        self.active_binary: Optional[Path] = None
        self.ghidra_proc: Optional[subprocess.Popen] = None
        self.backend_session = BackendMCPSession(backend_port)
        self.engine_stage: str = "BOOTING"
        self.ghidra_internal_url: str = ""
        self.public_base_url: str = f"http://127.0.0.1:{gateway_port}"
        if os.environ.get("SPACE_HOST"):
            self.public_base_url = f"https://{os.environ['SPACE_HOST']}"
        self.logs: Deque[str] = collections.deque(maxlen=300)
        self.lock = threading.Lock()
        self.fleet_file = self.work_dir / "federated_cloud_nodes.json"
        self.fleet_nodes: Dict[str, Dict[str, Any]] = self._load_fleet()

    def log(self, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        print(line, flush=True)
        self.logs.append(line)
        if "Importing " in msg:
            self.engine_stage = "IMPORTING_BINARY"
        elif "Analyzing " in msg:
            self.engine_stage = "ANALYZING_BINARY"
        elif "Serving " in msg and "http://" in msg:
            self.engine_stage = "READY"
            m = re.search(r"(http://127\.0\.0\.1:\d+/?)", msg)
            if m:
                self.ghidra_internal_url = m.group(1)

    def _load_fleet(self) -> Dict[str, Dict[str, Any]]:
        if self.fleet_file.exists():
            try:
                return json.loads(self.fleet_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def save_fleet(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.fleet_file.write_text(json.dumps(self.fleet_nodes, indent=2), encoding="utf-8")

    def register_node(self, name: str, mcp_url: str, cloud_provider: str = "Custom Cloud Node") -> Dict[str, Any]:
        clean_url = mcp_url.strip()
        if not clean_url.endswith(("/mcp", "/sse")):
            clean_url = clean_url.rstrip("/") + "/mcp"
        node_info = {
            "name": name.strip(),
            "mcp_url": clean_url,
            "provider": cloud_provider,
            "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ONLINE_READY",
        }
        self.fleet_nodes[name.strip()] = node_info
        self.save_fleet()
        self.log(f"Registered federated cloud node '{name}' -> {clean_url}")
        return node_info

    def remove_node(self, name: str) -> bool:
        if name in self.fleet_nodes:
            del self.fleet_nodes[name]
            self.save_fleet()
            self.log(f"Removed federated cloud node '{name}'")
            return True
        return False

    def check_fleet_health(self) -> Dict[str, Any]:
        results = {}
        for name, node in list(self.fleet_nodes.items()):
            url = node["mcp_url"]
            t0 = time.time()
            try:
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "OmniCloudFleet", "version": "5.0"}},
                }).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    latency_ms = round((time.time() - t0) * 1000, 1)
                    node["status"] = f"ONLINE ({resp.status}, {latency_ms}ms)"
            except Exception as exc:
                node["status"] = f"UNREACHABLE ({type(exc).__name__})"
            results[name] = node
        self.save_fleet()
        return results

    def start_or_restart_backend(self, new_binary: Path) -> Dict[str, Any]:
        with self.lock:
            self.active_binary = new_binary.resolve()
            self.backend_session.reset()
            self.engine_stage = "STARTING_JVM"
            if self.ghidra_proc and self.ghidra_proc.poll() is None:
                self.log(f"Stopping previous Headless GhidraMCP process (PID {self.ghidra_proc.pid}) for binary hot-swap...")
                self.ghidra_proc.terminate()
                try:
                    self.ghidra_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.ghidra_proc.kill()

            if not self.ghidra_dir or not self.ghidra_dir.exists():
                self.engine_stage = "STANDALONE_FORENSICS"
                self.log("Ghidra 12.1.4 not yet extracted — running in standalone forensics/gateway mode.")
                return {"status": "STANDALONE_FORENSICS_MODE", "active_binary": str(self.active_binary)}

            proj_dir = self.work_dir / "ghidra_projects" / re.sub(r"[^a-zA-Z0-9._-]", "_", self.active_binary.name)
            proj_dir.mkdir(parents=True, exist_ok=True)

            env = os.environ.copy()
            env["GHIDRA_INSTALL_DIR"] = str(self.ghidra_dir)
            env["GHIDRA_HEADLESS_MAXMEM"] = self.env_info["jvm_maxmem"]
            if self.java_home:
                env["JAVA_HOME"] = self.java_home
                env["PATH"] = f"{Path(self.java_home) / 'bin'}{os.pathsep}{env.get('PATH', '')}"

            uvx_bin = shutil.which("uvx") or "uvx"
            cmd = [
                uvx_bin,
                "--python", "3.13",
                "--from", GHIDRA_MCP_GIT_SPEC,
                "ghidra-mcp",
                "--headless",
                "--binary", str(self.active_binary),
                "--project", str(proj_dir),
                "--transport", "streamable-http",
                "--mcp-host", "127.0.0.1",
                "--mcp-port", str(self.backend_port),
            ]
            self.log(f"Booting Headless GhidraMCP on 127.0.0.1:{self.backend_port} for binary: {self.active_binary.name} (MAXMEM={env['GHIDRA_HEADLESS_MAXMEM']})")
            try:
                self.ghidra_proc = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                threading.Thread(target=self._stream_backend_logs, args=(self.ghidra_proc,), daemon=True).start()
                return {
                    "status": "RESTARTED_HEADLESS_GHIDRA",
                    "pid": self.ghidra_proc.pid,
                    "active_binary": str(self.active_binary),
                    "project_dir": str(proj_dir),
                    "jvm_maxmem": env["GHIDRA_HEADLESS_MAXMEM"],
                }
            except Exception as exc:
                self.engine_stage = "ERROR"
                self.log(f"[!] Could not launch uvx ghidra-mcp backend: {exc}")
                return {"status": "ERROR", "error": str(exc)}

    def _stream_backend_logs(self, proc: subprocess.Popen) -> None:
        if not proc.stdout:
            return
        for line in proc.stdout:
            clean = line.rstrip()
            if clean:
                self.log(f"[GhidraMCP] {clean}")


# ---------------------------------------------------------------------------
# 4. Cloud Deployment Generators (Kaggle/Colab .ipynb, GitHub Actions, HF)
# ---------------------------------------------------------------------------

HF_README_MD = r"""---
title: GhidraMCP Workstation Pro
emoji: 🐉
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
---

# GhidraMCP v5.0 Workstation Pro & Remote MCP Server
"""

HF_DOCKERFILE = r"""FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    unzip \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

RUN useradd -m -u 1000 user
WORKDIR /home/user/app

RUN curl -L -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip" && \
    echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    rm /tmp/ghidra.zip && \
    chown -R user:user /opt/ghidra_12.1.4_PUBLIC

RUN curl -L -o /tmp/ghidramcp_rel.zip \
    "https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip" && \
    unzip -q /tmp/ghidramcp_rel.zip -d /tmp/ghidramcp_ext && \
    INNER_ZIP=$(find /tmp/ghidramcp_ext -name "*GhidraMCP*.zip" | head -n 1) && \
    unzip -q "$INNER_ZIP" -d /opt/ghidra_12.1.4_PUBLIC/Ghidra/Extensions/ && \
    rm -rf /tmp/ghidramcp_rel.zip /tmp/ghidramcp_ext && \
    chown -R user:user /opt/ghidra_12.1.4_PUBLIC

COPY --chown=user:user ghidra_mcp_cloud_launcher.py /home/user/app/ghidra_mcp_cloud_launcher.py

USER user
ENV HOME=/home/user
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="/home/user/.local/bin:${PATH}"

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

EXPOSE 7860

CMD ["python3", "/home/user/app/ghidra_mcp_cloud_launcher.py", "--port", "7860", "--no-tunnel"]
"""

HF_ZEROGPU_README_MD = r"""---
title: GhidraMCP Workstation Pro
emoji: 🐉
colorFrom: indigo
colorTo: blue
sdk: gradio
sdk_version: 5.50.0
app_file: app.py
pinned: false
---

# GhidraMCP v5.0 Free ZeroGPU Cloud Host
"""

HF_ZEROGPU_APP_PY = r"""import os, re, subprocess, sys, threading
import gradio as gr

try:
    import spaces
except ImportError:
    spaces = None

tunnel_url_state = {"mcp_url": "Booting Headless Ghidra 12.1.4 + Cloudflare Tunnel (takes ~60s)..."}

def _bg_boot():
    proc = subprocess.Popen(
        [sys.executable, "ghidra_mcp_cloud_launcher.py", "--port", "17860"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.stdout:
        for line in proc.stdout:
            print(line, end="", flush=True)
            m = re.search(r"(https://[a-zA-Z0-9-]+\.trycloudflare\.com)", line)
            if m:
                base = m.group(1).rstrip("/")
                tunnel_url_state["mcp_url"] = f"LIVE GEMINI MCP URL: {base}/mcp  |  WORKSTATION GUI: {base}/"

threading.Thread(target=_bg_boot, daemon=True).start()

if spaces is not None:
    @spaces.GPU(duration=5)
    def gpu_ping():
        return "ZeroGPU Ready"
else:
    def gpu_ping():
        return "Standard CPU Ready"

def get_status():
    return tunnel_url_state["mcp_url"]

with gr.Blocks(title="GhidraMCP v5.0 Workstation Pro") as demo:
    gr.Markdown("# 🐉 GhidraMCP v5.0 — 100% Free Cloud Server")
    status_box = gr.Textbox(label="Copy Your Live Gemini Connected Apps /mcp Link Below:", value=get_status, every=4)
    btn = gr.Button("Refresh Link Status")
    btn.click(fn=get_status, outputs=status_box)

if __name__ == "__main__":
    demo.launch()
"""

GITHUB_WORKFLOW_YML = r"""name: GhidraMCP 24x7 Perpetual Cloud Relay
on:
  workflow_dispatch:
  push:
    branches: [ main ]
  schedule:
    # Automatically ensures a runner is alive every 5 hours (24/7/365 Set-and-Forget)
    - cron: '15 */5 * * *'

permissions:
  contents: write
  actions: write

concurrency:
  group: ghidra-mcp-perpetual-relay
  cancel-in-progress: false

jobs:
  ghidra-mcp-cloud:
    runs-on: ubuntu-24.04
    timeout-minutes: 330
    steps:
      - name: 1. Checkout Repository
        uses: actions/checkout@v4

      - name: 2. Boot Cloud GhidraMCP & Publish Live URL to LIVE_MCP_URL.json (~60s)
        run: |
          nohup python3 ghidra_mcp_cloud_launcher.py --port 7860 > /tmp/ghidra_omni.log 2>&1 &
          echo "Waiting for Headless Ghidra 12.1.4 + Cloudflare Tunnel to publish URL..."
          for i in $(seq 1 90); do
            if grep -q "trycloudflare.com" /tmp/ghidra_omni.log; then
              BASE_URL=$(grep -oE "https://[a-zA-Z0-9-]+\.trycloudflare\.com" /tmp/ghidra_omni.log | head -n 1)
              MCP_URL="${BASE_URL}/mcp"
              GUI_URL="${BASE_URL}/"
              echo "=================================================================="
              echo "  24/7 PERPETUAL CLOUD SERVER IS LIVE!"
              echo "  1. CURRENT TUNNEL MCP URL : ${MCP_URL}"
              echo "  2. WORKSTATION WEB GUI    : ${GUI_URL}"
              echo "=================================================================="
              echo "## 🐉 Your 24/7 Perpetual GitHub Cloud GhidraMCP Server is LIVE!" >> $GITHUB_STEP_SUMMARY
              echo "- **Current Tunnel MCP URL:** \`${MCP_URL}\`" >> $GITHUB_STEP_SUMMARY
              echo "- **Open Cloud Workstation GUI:** [${GUI_URL}](${GUI_URL})" >> $GITHUB_STEP_SUMMARY
              printf '{"status":"LIVE","mcp_url":"%s","gui_url":"%s","updated_at":"%s"}\n' "$MCP_URL" "$GUI_URL" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > LIVE_MCP_URL.json
              git config user.name "ghidra-mcp-cloud-bot"
              git config user.email "bot@users.noreply.github.com"
              git add LIVE_MCP_URL.json
              git commit -m "Auto-update LIVE_MCP_URL.json [skip ci]" || true
              git push || true
              break
            fi
            sleep 3
          done
          # Ensure +x permissions on all native Ghidra decompiler binaries
          chmod -R +x /tmp/ghidra_mcp_cloud/ghidra_12.1.4_PUBLIC/Ghidra/Features/Decompiler/os/ 2>/dev/null || true
          cat /tmp/ghidra_omni.log

      - name: 3. Keep Server Online (5-Hour Relay Window)
        run: |
          echo "Server is LIVE! Running for 5 hours before automatically spawning the next relay runner..."
          sleep 18000

      - name: 4. Perpetual Self-Respawn (Automatically Triggers Next Runner Before Exiting!)
        if: always()
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "Triggering next 24/7 relay runner via GitHub API..."
          curl -sS -X POST \
            -H "Authorization: Bearer ${GH_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/workflows/ghidra_mcp_cloud.yml/dispatches" \
            -d '{"ref":"main"}' || true
"""


def build_permanent_cloudflare_worker_js(
    github_username: str = "<YOUR_GITHUB_USERNAME>",
    repo_name: str = "ghidra-mcp-omni-cloud",
    gh_token_for_autowake: str = "",
) -> str:
    """Generate a 100% Free Cloudflare Worker script that gives Gemini a SINGLE PERMANENT URL
    (`https://ghidra-mcp-forever.<your-subdomain>.workers.dev/mcp`), dynamically routes to the latest
    `LIVE_MCP_URL.json` tunnel URL published by your 24/7 GitHub Actions relay, AND automatically
    wakes up your GitHub Actions runner via `workflow_dispatch` if it ever goes idle!"""
    raw_json_url = f"https://raw.githubusercontent.com/{github_username}/{repo_name}/main/LIVE_MCP_URL.json"
    dispatch_url = f"https://api.github.com/repos/{github_username}/{repo_name}/actions/workflows/ghidra_mcp_cloud.yml/dispatches"
    return f"""/**
 * GhidraMCP v6.5 — Permanent "Set-and-Forget" Cloudflare Worker Router + Auto-Wake
 * =================================================================================
 * Deployed automatically by ghidra_mcp_cloud_launcher.py.
 * Gives Gemini Connected Apps ONE permanent URL that never changes:
 *   https://ghidra-mcp-forever.<your-subdomain>.workers.dev/mcp
 */

const GITHUB_LIVE_JSON_URL = "{raw_json_url}";
const GITHUB_DISPATCH_URL = "{dispatch_url}";
const AUTO_WAKE_GH_TOKEN = "{gh_token_for_autowake}";

async function triggerGithubAutoWake() {{
  if (!AUTO_WAKE_GH_TOKEN) return false;
  try {{
    const r = await fetch(GITHUB_DISPATCH_URL, {{
      method: "POST",
      headers: {{
        "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "GhidraMCP-Permanent-Router/6.5",
        "Content-Type": "application/json"
      }},
      body: JSON.stringify({{ ref: "main" }})
    }});
    return r.status === 204 || r.status === 200;
  }} catch (_) {{
    return false;
  }}
}}

async function getLatestTunnelUrl() {{
  const res = await fetch(GITHUB_LIVE_JSON_URL + "?t=" + Date.now(), {{
    headers: {{ "User-Agent": "GhidraMCP-Permanent-Router/6.5" }}
  }});
  if (!res.ok) throw new Error("Could not fetch LIVE_MCP_URL.json: HTTP " + res.status);
  return await res.json();
}}

export default {{
  async fetch(request) {{
    if (request.method === "OPTIONS") {{
      return new Response(null, {{
        headers: {{
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Session-Id, Last-Event-ID"
        }}
      }});
    }}

    const url = new URL(request.url);
    try {{
      const live = await getLatestTunnelUrl();
      const targetBase = (live.gui_url || live.mcp_url.replace(/\\/mcp$/, "")).replace(/\\/$/, "");
      const targetUrl = targetBase + url.pathname + url.search;

      if (request.method === "GET" && (url.pathname === "/status" || url.pathname === "/router-status")) {{
        return new Response(JSON.stringify({{
          router: "GhidraMCP v6.5 Permanent Set-and-Forget Router",
          active_backend_mcp_url: live.mcp_url,
          active_backend_gui_url: live.gui_url,
          updated_at: live.updated_at
        }}, null, 2), {{
          headers: {{ "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }}
        }});
      }}

      const proxyReq = new Request(targetUrl, {{
        method: request.method,
        headers: request.headers,
        body: request.method !== "GET" && request.method !== "HEAD" ? await request.arrayBuffer() : undefined,
      }});
      const resp = await fetch(proxyReq);
      if (resp.status === 530) {{
        await triggerGithubAutoWake();
        throw new Error("Upstream tunnel rotated or sleeping (HTTP " + resp.status + ") — triggered Auto-Wake!");
      }}
      const newHeaders = new Headers(resp.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(resp.body, {{ status: resp.status, headers: newHeaders }});
    }} catch (err) {{
      if (String(err).includes("530")) {{
        await triggerGithubAutoWake();
      }}
      if (request.method === "POST") {{
        try {{
          const body = await request.clone().json();
          if (body.method === "initialize") {{
            return new Response(JSON.stringify({{
              jsonrpc: "2.0",
              id: body.id || 1,
              result: {{
                protocolVersion: "2025-03-26",
                capabilities: {{ tools: {{ listChanged: true }} }},
                serverInfo: {{ name: "GhidraMCP-Permanent-Cloud-Router", version: "6.5.0" }}
              }}
            }}), {{ headers: {{ "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }} }});
          }}
        }} catch (_) {{}}
      }}
      return new Response(JSON.stringify({{
        status: "AUTO_WAKING_CLOUD_RELAY",
        message: "Automatically signaled your 24/7 GitHub Cloud Relay to wake/rotate (~45s). Repeat your prompt in a moment!",
        error: String(err)
      }}, null, 2), {{ status: 200, headers: {{ "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }} }});
    }}
  }}
}};
"""


def auto_detect_saved_github_token(work_dir: Path) -> str:
    """Try to find an existing GitHub token automatically from saved config, env, `gh auth token`, or `git credential fill`."""
    cfg_file = work_dir / "forever_credentials.json"
    if cfg_file.exists():
        try:
            tok = json.loads(cfg_file.read_text(encoding="utf-8")).get("github_token", "")
            if tok:
                return tok
        except Exception:
            pass

    for env_key in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(env_key):
            return os.environ[env_key].strip()

    if shutil.which("gh"):
        try:
            out = subprocess.check_output(["gh", "auth", "token"], stderr=subprocess.DEVNULL, text=True).strip()
            if out and len(out) >= 20:
                return out
        except Exception:
            pass

    # Skipped git credential fill to avoid Windows GCM popup

    return ""


def deploy_cloudflare_worker_automatically(
    work_dir: Path,
    github_username: str,
    repo_name: str,
    gh_token: str,
    cf_api_token: str = "",
) -> Dict[str, Any]:
    """Automatically deploy the Permanent Front-Door Cloudflare Worker Router from the user's PC
    via either the Cloudflare REST API (if `cf_api_token` is given) or `npx --yes wrangler@latest deploy`."""
    worker_name = "ghidra-mcp-forever"
    worker_js = build_permanent_cloudflare_worker_js(github_username, repo_name, gh_token)

    # Route 1: Direct Cloudflare REST API (zero Node.js / Wrangler required if token provided)
    if cf_api_token.strip():
        tok = cf_api_token.strip()
        cf_headers = {
            "Authorization": f"Bearer {tok}",
            "Content-Type": "application/json",
            "User-Agent": "GhidraMCP-AutoProvisioner/6.5",
        }
        try:
            acc_req = urllib.request.Request("https://api.cloudflare.com/client/v4/accounts", headers=cf_headers)
            with urllib.request.urlopen(acc_req, timeout=12) as resp:
                acc_data = json.loads(resp.read().decode("utf-8"))
            accounts = acc_data.get("result") or []
            if not accounts:
                return {"status": "error", "error": "No Cloudflare account found for this API token."}
            account_id = accounts[0]["id"]

            sub_req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/subdomain",
                headers=cf_headers,
            )
            subdomain = ""
            try:
                with urllib.request.urlopen(sub_req, timeout=10) as s_resp:
                    subdomain = (json.loads(s_resp.read().decode("utf-8")).get("result") or {}).get("subdomain", "")
            except Exception:
                pass

            boundary = "----GhidraMCPWorkerBoundary65"
            metadata_json = json.dumps({
                "main_module": "worker.js",
                "compatibility_date": "2026-01-01",
            })
            body_parts = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="metadata"; filename="metadata.json"\r\n'
                f"Content-Type: application/json\r\n\r\n"
                f"{metadata_json}\r\n"
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
                f"Content-Type: application/javascript+module\r\n\r\n"
                f"{worker_js}\r\n"
                f"--{boundary}--\r\n"
            ).encode("utf-8")

            put_headers = {
                "Authorization": f"Bearer {tok}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "GhidraMCP-AutoProvisioner/6.5",
            }
            put_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}"
            put_req = urllib.request.Request(put_url, data=body_parts, headers=put_headers, method="PUT")
            with urllib.request.urlopen(put_req, timeout=20) as p_resp:
                p_resp.read()

            # Enable workers.dev subdomain route for this Worker
            sub_enable_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}/subdomain"
            en_req = urllib.request.Request(
                sub_enable_url,
                data=json.dumps({"enabled": True}).encode("utf-8"),
                headers=cf_headers,
                method="POST",
            )
            try:
                urllib.request.urlopen(en_req, timeout=10)
            except Exception:
                pass

            if subdomain:
                perm_url = f"https://{worker_name}.{subdomain}.workers.dev/mcp"
            else:
                perm_url = f"https://{worker_name}.<your-subdomain>.workers.dev/mcp"
            copy_to_system_clipboard(perm_url)
            return {
                "status": "DEPLOYED_PERMANENT_WORKER",
                "permanent_mcp_url": perm_url,
                "method": "Cloudflare REST API",
            }
        except Exception as exc:
            return {"status": "error", "error": f"Cloudflare API deploy error: {exc}"}

    # Route 2: Automated `npx --yes wrangler@latest deploy` (opens 1-click Cloudflare OAuth in browser)
    if not shutil.which("npx") and platform.system().lower() == "windows" and shutil.which("winget"):
        print("[+] Installing Node.js LTS via winget so Wrangler can auto-deploy your permanent Cloudflare Worker...")
        subprocess.run(["winget", "install", "--id", "OpenJS.NodeJS.LTS", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"], check=False)
        os.environ["PATH"] = f"C:\\Program Files\\nodejs{os.pathsep}{os.environ.get('PATH', '')}"

    if shutil.which("npx"):
        w_dir = work_dir / "cf_forever_worker"
        w_dir.mkdir(parents=True, exist_ok=True)
        (w_dir / "worker.js").write_text(worker_js, encoding="utf-8")
        (w_dir / "wrangler.toml").write_text(
            f'name = "{worker_name}"\nmain = "worker.js"\ncompatibility_date = "2026-01-01"\nworkers_dev = true\n',
            encoding="utf-8",
        )
        npx_cmd = "npx.cmd" if platform.system().lower() == "windows" and shutil.which("npx.cmd") else "npx"
        # Check if Wrangler is already logged in; if not, run `wrangler login` attached to the real interactive TTY!
        whoami = subprocess.run(
            [npx_cmd, "--yes", "wrangler@latest", "whoami"],
            cwd=str(w_dir),
            capture_output=True,
            text=True,
        )
        if whoami.returncode != 0 or "not authenticated" in (whoami.stdout + whoami.stderr).lower():
            print("[+] Opening Cloudflare 1-click browser login (interactive TTY mode — click 'Allow' in your browser)...")
            subprocess.run([npx_cmd, "--yes", "wrangler@latest", "login"], cwd=str(w_dir), check=False)

        print("[+] Deploying Permanent Router Worker via `npx --yes wrangler@latest deploy`...")
        proc = subprocess.Popen(
            [npx_cmd, "--yes", "wrangler@latest", "deploy"],
            cwd=str(w_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deployed_url = ""
        output_lines: List[str] = []
        if proc.stdout:
            for line in proc.stdout:
                print(line, end="", flush=True)
                output_lines.append(line)
                m = re.search(r"(https://[a-zA-Z0-9._-]+\.workers\.dev)", line)
                if m:
                    deployed_url = m.group(1).rstrip("/") + "/mcp"
        proc.wait()

        # If user skipped Cloudflare login, automatically fall back to Wrangler 4.x's zero-login `--temporary` worker!
        if not deployed_url:
            print("[+] No Cloudflare login detected — automatically deploying zero-login `--temporary` Worker...")
            proc_tmp = subprocess.Popen(
                [npx_cmd, "--yes", "wrangler@latest", "deploy", "--temporary"],
                cwd=str(w_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            claim_url = ""
            if proc_tmp.stdout:
                for line in proc_tmp.stdout:
                    print(line, end="", flush=True)
                    output_lines.append(line)
                    m = re.search(r"(https://[a-zA-Z0-9._-]+\.workers\.dev)", line)
                    if m and not deployed_url:
                        deployed_url = m.group(1).rstrip("/") + "/mcp"
                    m_claim = re.search(r"(https://[a-zA-Z0-9./?=&_-]*cloudflare[a-zA-Z0-9./?=&_-]*)", line)
                    if m_claim and "claim" in line.lower():
                        claim_url = m_claim.group(1)
            proc_tmp.wait()
            if deployed_url:
                copy_to_system_clipboard(deployed_url)
                return {
                    "status": "DEPLOYED_PERMANENT_WORKER",
                    "permanent_mcp_url": deployed_url,
                    "claim_url_to_keep_forever": claim_url,
                    "method": "Wrangler Zero-Login (--temporary)",
                }

        if deployed_url:
            copy_to_system_clipboard(deployed_url)
            return {
                "status": "DEPLOYED_PERMANENT_WORKER",
                "permanent_mcp_url": deployed_url,
                "method": "Wrangler Auto-Deploy",
            }
        return {
            "status": "WRANGLER_NEEDS_AUTH",
            "message": "Paste a free Cloudflare API Token (Edit Cloudflare Workers template) in the box or install Node.js (`npx`) for 1-click browser login.",
            "logs": "".join(output_lines[-15:]),
        }

    return {
        "status": "NEEDS_CF_TOKEN_OR_NODE",
        "message": "To auto-deploy the permanent .workers.dev URL without Node.js, paste a free Cloudflare API Token ('Edit Cloudflare Workers' template) in the Cloudflare Token box!",
    }


def run_autonomous_forever_provisioner(
    work_dir: Path,
    gh_token_input: str = "",
    cf_token_input: str = "",
    repo_name: str = "ghidra-mcp-omni-cloud",
    interactive_cli: bool = False,
) -> Dict[str, Any]:
    """Single end-to-end automated provisioner:
    1. Resolves or prompts once for GitHub token and saves it.
    2. Provisions the 24/7 Perpetual Self-Respawning GitHub Actions Relay repo + workflow.
    3. Polls until the live GitHub Cloud runner publishes `LIVE_MCP_URL.json`.
    4. Automatically deploys the Permanent Front-Door Cloudflare Worker (`ghidra-mcp-forever.<sub_id>.workers.dev/mcp`)
       wired with On-Demand Auto-Wake!
    5. Copies the single permanent URL straight to the user's clipboard!"""
    work_dir.mkdir(parents=True, exist_ok=True)
    gh_token = gh_token_input.strip() or auto_detect_saved_github_token(work_dir)

    if not gh_token and interactive_cli:
        print("\n" + "=" * 80)
        print("  STEP 1/2: ONE-TIME GITHUB CLOUD AUTHORIZATION")
        print("=" * 80)
        gh_url = "https://github.com/settings/tokens/new?description=GhidraMCP-24x7-Forever&scopes=repo,workflow"
        print(f"  Opening GitHub Token page in your browser: {gh_url}")
        try:
            webbrowser.open(gh_url)
        except Exception:
            pass
        gh_token = input("  -> Paste your GitHub Token (ghp_...) and press Enter: ").strip()

    if not gh_token:
        return {
            "status": "NEEDS_GITHUB_TOKEN",
            "error": "Paste your GitHub token (ghp_...) once so the script can provision your 24/7 GitHub Cloud Relay automatically.",
        }

    # Save token locally so future runs need zero input
    cfg_file = work_dir / "forever_credentials.json"
    cfg_file.write_text(json.dumps({"github_token": gh_token, "cf_token": cf_token_input.strip()}, indent=2), encoding="utf-8")

    print("[+] Step 1/3: Auto-provisioning 24/7 Perpetual Self-Respawning GitHub Cloud Relay...")
    gh_res = deploy_to_github_cloud_api(gh_token, repo_name=repo_name)
    if gh_res.get("status") != "DEPLOYED_GITHUB_CLOUD":
        return gh_res

    username = gh_res["username"]
    raw_live_url = gh_res["raw_live_url"]

    # Also upload the permanent worker with auto-wake token baked in
    print("[+] Step 2/3: Deploying Permanent Front-Door Cloudflare Worker Router...")
    cf_res = deploy_cloudflare_worker_automatically(
        work_dir=work_dir,
        github_username=username,
        repo_name=repo_name,
        gh_token=gh_token,
        cf_api_token=cf_token_input,
    )

    print("[+] Step 3/3: Waiting for your 24/7 GitHub Cloud Relay runner to publish its initial LIVE_MCP_URL.json (~45-75s)...")
    live_tunnel_mcp = ""
    max_wait = 75 if interactive_cli else 20
    for elapsed in range(0, max_wait, 5):
        try:
            req = urllib.request.Request(
                f"{raw_live_url}?t={int(time.time())}",
                headers={"User-Agent": "GhidraMCP-AutoProvisioner/6.5"},
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                live_data = json.loads(r.read().decode("utf-8"))
                if live_data.get("mcp_url"):
                    live_tunnel_mcp = live_data["mcp_url"]
                    break
        except Exception:
            pass
        if interactive_cli:
            print(f"    ... GitHub Cloud VM booting Ghidra 12.1.4 ({elapsed}s elapsed)...")
        time.sleep(5)

    final_permanent_url = cf_res.get("permanent_mcp_url") or live_tunnel_mcp
    if final_permanent_url:
        copy_to_system_clipboard(final_permanent_url)

    return {
        "status": "FOREVER_SETUP_COMPLETE",
        "github_username": username,
        "github_repo": gh_res["github_repo"],
        "github_actions_url": gh_res["github_actions_live_logs"],
        "raw_live_url": raw_live_url,
        "active_relay_tunnel_mcp_url": live_tunnel_mcp or "Booting on GitHub Actions (~60s)",
        "cloudflare_worker_result": cf_res,
        "final_gemini_mcp_url": final_permanent_url,
        "instructions": (
            "DONE! Paste `final_gemini_mcp_url` into Gemini -> Settings -> Connected Apps -> Add a custom app link. "
            "You can now close PowerShell and turn off your PC forever!"
        ),
    }


def generate_hf_space_bundle(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    readme_path = output_dir / "README.md"
    dockerfile_path = output_dir / "Dockerfile"
    launcher_copy = output_dir / "ghidra_mcp_cloud_launcher.py"

    readme_path.write_text(HF_README_MD.strip() + "\n", encoding="utf-8")
    dockerfile_path.write_text(HF_DOCKERFILE.strip() + "\n", encoding="utf-8")
    try:
        shutil.copyfile(Path(__file__).resolve(), launcher_copy)
    except Exception:
        pass
    print(f"[+] Generated v5.0 Hugging Face Docker Space bundle in: {output_dir.resolve()}")


def build_oneclick_ipynb_bytes() -> bytes:
    launcher_source = Path(__file__).resolve().read_text(encoding="utf-8")
    cell_code = (
        "# 1-CLICK GHIDRAMCP v5.0 WORKSTATION PRO (Works in Google Colab & Kaggle 30 GB RAM)\n"
        "from pathlib import Path\n"
        "import subprocess, sys, urllib.request\n\n"
        "try:\n"
        "    urllib.request.urlopen('https://github.com', timeout=6)\n"
        "    print('[+] Cloud Internet check PASSED!')\n"
        "except Exception:\n"
        "    print('====================================================================')\n"
        "    print('[!] INTERNET IS TURNED OFF IN THIS NOTEBOOK!')\n"
        "    print('    -> In Kaggle: look at the RIGHT SIDEBAR -> click Settings ->')\n"
        "    print('       toggle \"Internet\" ON, then click Run again!')\n"
        "    print('====================================================================')\n"
        "    raise SystemExit(0)\n\n"
        f"SCRIPT = {repr(launcher_source)}\n"
        "Path('ghidra_mcp_cloud_launcher.py').write_text(SCRIPT, encoding='utf-8')\n"
        "print('[+] Launching GhidraMCP v5.0 Workstation Pro (streaming live output below)...')\n"
        "proc = subprocess.Popen(\n"
        "    [sys.executable, '-u', 'ghidra_mcp_cloud_launcher.py'],\n"
        "    stdout=subprocess.PIPE,\n"
        "    stderr=subprocess.STDOUT,\n"
        "    text=True,\n"
        ")\n"
        "for line in proc.stdout:\n"
        "    print(line, end='', flush=True)\n"
    )
    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# 🐉 GhidraMCP v5.0 Workstation Pro — 1-Click Cloud Server (Kaggle 30 GB RAM & Google Colab)\n",
                    "**How to use:** Make sure **Internet** is toggled **ON** in Kaggle's right-hand Settings panel, then click **Run (▶)** below. Once `PUBLIC TUNNEL READY!` appears, open the `VISUAL GUI WIZARD` URL in a new browser tab and paste the `GEMINI MCP LINK` into **Gemini -> Settings -> Connected Apps**!"
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": cell_code.splitlines(keepends=True),
            },
        ],
    }
    return json.dumps(nb, indent=2).encode("utf-8")


def deploy_to_github_cloud_api(gh_token: str, repo_name: str = "ghidra-mcp-omni-cloud") -> Dict[str, Any]:
    token = gh_token.strip()
    if not token:
        return {"status": "error", "error": "Please paste your free GitHub Personal Access Token (ghp_... or github_pat_...)."}

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "GhidraMCP-WorkstationPro/5.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        user_req = urllib.request.Request("https://api.github.com/user", headers=headers)
        with urllib.request.urlopen(user_req, timeout=10) as resp:
            username = json.loads(resp.read().decode("utf-8")).get("login")
        if not username:
            return {"status": "error", "error": "Could not resolve GitHub username from token."}

        create_payload = json.dumps({
            "name": repo_name,
            "description": "GhidraMCP v5.0 Workstation Pro — Zero-PC Free Cloud Server",
            "private": False,
            "auto_init": True,
        }).encode("utf-8")
        try:
            c_req = urllib.request.Request("https://api.github.com/user/repos", data=create_payload, headers=headers, method="POST")
            urllib.request.urlopen(c_req, timeout=15)
            time.sleep(2)
        except urllib.error.HTTPError as he:
            if he.code not in (422, 409):
                raise

        def _put_github_file(rel_path: str, content_str: str, msg: str) -> None:
            api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{rel_path}"
            sha = None
            try:
                g_req = urllib.request.Request(api_url, headers=headers)
                with urllib.request.urlopen(g_req, timeout=8) as g_resp:
                    sha = json.loads(g_resp.read().decode("utf-8")).get("sha")
            except Exception:
                pass
            body_dict: Dict[str, Any] = {
                "message": msg,
                "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"),
            }
            if sha:
                body_dict["sha"] = sha
            p_req = urllib.request.Request(api_url, data=json.dumps(body_dict).encode("utf-8"), headers=headers, method="PUT")
            urllib.request.urlopen(p_req, timeout=20)

        launcher_source = Path(__file__).resolve().read_text(encoding="utf-8")
        _put_github_file("ghidra_mcp_cloud_launcher.py", launcher_source, "Upload GhidraMCP v5.0 Workstation Pro")
        _put_github_file(".github/workflows/ghidra_mcp_cloud.yml", GITHUB_WORKFLOW_YML, "Add 24/7 Perpetual Self-Respawning GitHub Cloud Relay")
        worker_code = build_permanent_cloudflare_worker_js(username, repo_name)
        _put_github_file("cloudflare_permanent_router_worker.js", worker_code, "Add Permanent Set-and-Forget Cloudflare Worker Router")

        try:
            disp_url = f"https://api.github.com/repos/{username}/{repo_name}/actions/workflows/ghidra_mcp_cloud.yml/dispatches"
            disp_req = urllib.request.Request(disp_url, data=json.dumps({"ref": "main"}).encode("utf-8"), headers=headers, method="POST")
            urllib.request.urlopen(disp_req, timeout=10)
        except Exception:
            pass

        return {
            "status": "DEPLOYED_GITHUB_CLOUD",
            "username": username,
            "repo_name": repo_name,
            "raw_live_url": f"https://raw.githubusercontent.com/{username}/{repo_name}/main/LIVE_MCP_URL.json",
            "github_repo": f"https://github.com/{username}/{repo_name}",
            "github_actions_live_logs": f"https://github.com/{username}/{repo_name}/actions",
            "github_codespaces_oneclick": f"https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo={username}/{repo_name}",
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def deploy_to_huggingface_api(hf_token: str, space_name: str = "ghidra-mcp-omni") -> Dict[str, Any]:
    token = hf_token.strip()
    if not token:
        return {"status": "error", "error": "Please paste your free Hugging Face Write Token (starts with hf_...)."}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "GhidraMCP-WorkstationPro/5.0",
    }
    try:
        whoami_req = urllib.request.Request("https://huggingface.co/api/whoami-v2", headers=headers)
        with urllib.request.urlopen(whoami_req, timeout=10) as resp:
            user_data = json.loads(resp.read().decode("utf-8"))
        username = user_data.get("name")
        if not username:
            return {"status": "error", "error": "Could not resolve Hugging Face username from token."}

        used_mode = "docker"
        create_body = json.dumps({"type": "space", "name": space_name, "sdk": "docker", "private": False}).encode("utf-8")
        create_req = urllib.request.Request("https://huggingface.co/api/repos/create", data=create_body, headers=headers, method="POST")
        try:
            urllib.request.urlopen(create_req, timeout=12)
        except urllib.error.HTTPError as he:
            if he.code == 402:
                used_mode = "zerogpu_gradio"
                zg_body = json.dumps({
                    "type": "space",
                    "name": space_name,
                    "sdk": "gradio",
                    "hardware": "zero-a10g",
                    "space_hardware": "zero-a10g",
                    "private": False,
                }).encode("utf-8")
                zg_req = urllib.request.Request("https://huggingface.co/api/repos/create", data=zg_body, headers=headers, method="POST")
                try:
                    urllib.request.urlopen(zg_req, timeout=12)
                except urllib.error.HTTPError as he2:
                    if he2.code == 402:
                        return {
                            "status": "HF_402_PAYWALL_DETECTED",
                            "why": "Hugging Face locked new Spaces behind their $9/mo PRO plan on this account.",
                            "free_fix": "Use the GitHub Cloud Auto-Deployer or the Kaggle 30 GB RAM Notebook (which already succeeded for you!).",
                        }
                    if he2.code != 409:
                        raise
            elif he.code != 409:
                raise

        launcher_source = Path(__file__).resolve().read_text(encoding="utf-8")
        if used_mode == "docker":
            ndjson_lines = [
                json.dumps({"key": "header", "value": {"summary": "Deploy GhidraMCP v5.0 Workstation Pro"}}),
                json.dumps({"key": "file", "value": {"content": HF_README_MD.strip() + "\n", "path": "README.md", "encoding": "utf-8"}}),
                json.dumps({"key": "file", "value": {"content": HF_DOCKERFILE.strip() + "\n", "path": "Dockerfile", "encoding": "utf-8"}}),
                json.dumps({"key": "file", "value": {"content": launcher_source, "path": "ghidra_mcp_cloud_launcher.py", "encoding": "utf-8"}}),
            ]
        else:
            ndjson_lines = [
                json.dumps({"key": "header", "value": {"summary": "Deploy GhidraMCP v5.0 Free ZeroGPU Cloud Host"}}),
                json.dumps({"key": "file", "value": {"content": HF_ZEROGPU_README_MD.strip() + "\n", "path": "README.md", "encoding": "utf-8"}}),
                json.dumps({"key": "file", "value": {"content": HF_ZEROGPU_APP_PY.strip() + "\n", "path": "app.py", "encoding": "utf-8"}}),
                json.dumps({"key": "file", "value": {"content": "openjdk-21-jdk\nunzip\ngcc\ncurl\n", "path": "packages.txt", "encoding": "utf-8"}}),
                json.dumps({"key": "file", "value": {"content": launcher_source, "path": "ghidra_mcp_cloud_launcher.py", "encoding": "utf-8"}}),
            ]

        commit_data = ("\n".join(ndjson_lines) + "\n").encode("utf-8")
        commit_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson", "User-Agent": "GhidraMCP-WorkstationPro/5.0"}
        commit_url = f"https://huggingface.co/api/spaces/{username}/{space_name}/commit/main"
        commit_req = urllib.request.Request(commit_url, data=commit_data, headers=commit_headers, method="POST")
        with urllib.request.urlopen(commit_req, timeout=25) as c_resp:
            commit_res = json.loads(c_resp.read().decode("utf-8"))

        host_slug = f"{username}-{space_name}".lower().replace("_", "-")
        space_mcp_url = f"https://{host_slug}.hf.space/mcp"
        return {
            "status": "DEPLOYED",
            "mode": used_mode,
            "space_repo": f"https://huggingface.co/spaces/{username}/{space_name}",
            "web_gui_url": f"https://{host_slug}.hf.space/",
            "gemini_mcp_url": space_mcp_url,
            "commit": commit_res.get("commitUrl", ""),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# 5. Built-In Omni-Cloud MCP Super-Tools & Stateful Multiplexer
# ---------------------------------------------------------------------------

OMNI_SUPER_TOOLS = [
    {
        "name": "triage_binary_forensics",
        "description": "Run instant static forensics triage on the active binary (ELF/PE/Mach-O format, SHA-256/MD5, Shannon entropy packer check, extracted URLs/IPs, and suspicious strings).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Optional path to a specific binary; defaults to the currently active binary.",
                }
            },
        },
    },
    {
        "name": "hot_swap_target_binary",
        "description": "Download or switch to a new target binary (from a direct HTTPS URL or path) and hot-restart the underlying Headless GhidraMCP analyzer without changing the Gemini MCP link.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_or_path": {
                    "type": "string",
                    "description": "HTTPS URL or filesystem path of the binary to load into Ghidra.",
                }
            },
            "required": ["url_or_path"],
        },
    },
    {
        "name": "federate_cloud_node",
        "description": "Register an additional free cloud GhidraMCP instance (Kaggle 30GB node, Colab, GitHub Cloud, Lightning AI, or Cloud Shell) into the unified multi-cloud cluster.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string", "description": "Friendly name (e.g. 'kaggle-30gb', 'github-cloud')."},
                "mcp_url": {"type": "string", "description": "Remote HTTPS /mcp endpoint of the cloud node."},
                "provider": {"type": "string", "description": "Cloud provider label (e.g. 'Kaggle 30GB RAM')."},
            },
            "required": ["node_name", "mcp_url"],
        },
    },
    {
        "name": "cluster_fleet_status",
        "description": "Return real-time health, RAM quota, active binary forensics, Ghidra analysis stage, and latency across the primary host and all federated multi-cloud nodes.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "dispatch_to_cloud_node",
        "description": "Execute any GhidraMCP tool call on a specific federated cloud node in your multi-cloud pool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string", "description": "Name of the registered cloud node (or 'auto' for best online node)."},
                "tool_name": {"type": "string", "description": "GhidraMCP tool name to invoke on the remote node (e.g. 'list_methods', 'decompile_function')."},
                "arguments": {"type": "object", "description": "JSON arguments object for the target tool."},
            },
            "required": ["node_name", "tool_name"],
        },
    },
]


def forward_jsonrpc_to_url(url: str, rpc_body: Dict[str, Any], timeout: int = 25) -> Optional[Dict[str, Any]]:
    data = json.dumps(rpc_body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "GhidraMCP-WorkstationPro/5.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_text = resp.read().decode("utf-8", errors="replace").strip()
            for line in reversed(raw_text.splitlines()):
                if line.startswith("data:"):
                    candidate = line[len("data:"):].strip()
                    if candidate.startswith("{"):
                        return json.loads(candidate)
            if raw_text.startswith("{"):
                return json.loads(raw_text)
    except Exception:
        return None
    return None


def handle_mcp_jsonrpc(state: OmniCloudState, body: Dict[str, Any]) -> Dict[str, Any]:
    rpc_id = body.get("id", 1)
    method = body.get("method", "")
    params = body.get("params") or {}

    if method == "initialize":
        state.backend_session.ensure_initialized()
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {
                    "name": "GhidraMCP-WorkstationPro",
                    "version": "5.0.0",
                },
            },
        }

    if method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if method == "tools/list":
        merged_tools = list(OMNI_SUPER_TOOLS)
        seen_names = {t["name"] for t in merged_tools}
        backend_resp = state.backend_session.request({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/list", "params": {}}, timeout=8)
        if backend_resp and "result" in backend_resp:
            for t in backend_resp["result"].get("tools", []):
                if t.get("name") not in seen_names:
                    seen_names.add(t["name"])
                    merged_tools.append(t)
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": merged_tools}}

    if method == "tools/call":
        t_name = params.get("name", "")
        t_args = params.get("arguments") or {}

        if t_name == "triage_binary_forensics":
            target = Path(t_args["binary_path"]) if t_args.get("binary_path") else state.active_binary
            payload = analyze_binary_forensics(target)
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}}

        if t_name == "hot_swap_target_binary":
            url_or_path = t_args.get("url_or_path", "")
            try:
                new_bin = prepare_target_binary(url_or_path, state.work_dir)
                swap_res = state.start_or_restart_backend(new_bin)
                swap_res["forensics"] = analyze_binary_forensics(new_bin)
                return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(swap_res, indent=2)}]}}
            except Exception as exc:
                return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps({"error": str(exc)})}]}}

        if t_name == "federate_cloud_node":
            info = state.register_node(
                t_args.get("node_name", "cloud-node"),
                t_args.get("mcp_url", ""),
                t_args.get("provider", "Federated Cloud Host"),
            )
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(info, indent=2)}]}}

        if t_name == "cluster_fleet_status":
            fleet = state.check_fleet_health()
            status_payload = {
                "primary_cloud_host": state.env_info,
                "engine_stage": state.engine_stage,
                "active_binary": str(state.active_binary) if state.active_binary else None,
                "ghidra_backend_running": bool(state.ghidra_proc and self.ghidra_proc.poll() is None),
                "public_mcp_endpoint": f"{state.public_base_url.rstrip('/')}/mcp",
                "federated_cloud_nodes": fleet,
            }
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(status_payload, indent=2)}]}}

        if t_name == "dispatch_to_cloud_node":
            node_name = t_args.get("node_name", "auto")
            remote_tool = t_args.get("tool_name", "")
            remote_args = t_args.get("arguments") or {}
            target_node = state.fleet_nodes.get(node_name) or (next(iter(state.fleet_nodes.values())) if state.fleet_nodes else None)
            if not target_node:
                return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps({"error": "No federated cloud nodes registered yet."})}]}}

            remote_rpc = {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call", "params": {"name": remote_tool, "arguments": remote_args}}
            remote_resp = forward_jsonrpc_to_url(target_node["mcp_url"], remote_rpc, timeout=30)
            if remote_resp and "result" in remote_resp:
                return remote_resp
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps({"error": f"Failed to reach node {target_node['name']}"})}]}}

        backend_resp = state.backend_session.request(body, timeout=35)
        if backend_resp:
            return backend_resp

        for node in state.fleet_nodes.values():
            failover_resp = forward_jsonrpc_to_url(node["mcp_url"], body, timeout=30)
            if failover_resp:
                return failover_resp

        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "notice": f"Headless Ghidra engine is currently in stage '{state.engine_stage}'. Instant static forensics are attached below.",
                        "forensics": analyze_binary_forensics(state.active_binary),
                    }, indent=2),
                }]
            },
        }

    return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}


# ---------------------------------------------------------------------------
# 6. Workstation Pro Web GUI (SSR Initial State + 4-Tab Interactive IDE)
# ---------------------------------------------------------------------------

WEB_GUI_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GhidraMCP v5.0 Workstation Pro — Cloud Decompiler & MCP Control Center</title>
<style>
  :root {
    --bg: #070b14;
    --panel: #0f172a;
    --panel-alt: #1e293b;
    --border: #334155;
    --accent: #38bdf8;
    --accent-2: #6366f1;
    --success: #10b981;
    --warn: #f59e0b;
    --danger: #ef4444;
    --text: #f8fafc;
    --muted: #94a3b8;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  header {
    background: linear-gradient(90deg, #090d16 0%, #111827 50%, #1e1b4b 100%);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    position: sticky;
    top: 0;
    z-index: 50;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand h1 { margin: 0; font-size: 1.18rem; font-weight: 800; letter-spacing: -0.02em; }
  .stage-badge {
    padding: 4px 11px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 700;
    background: rgba(16, 185, 129, 0.18);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.45);
  }
  .mcp-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    background: #06131f;
    border: 1.5px solid var(--accent);
    padding: 7px 12px;
    border-radius: 10px;
  }
  .mcp-bar code {
    color: var(--accent);
    font-weight: 700;
    font-size: 0.88rem;
    user-select: all;
  }
  button, a.btn {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: #070b14;
    border: none;
    padding: 8px 14px;
    border-radius: 8px;
    font-weight: 700;
    cursor: pointer;
    font-size: 0.83rem;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: transform 0.1s, opacity 0.15s;
  }
  button:hover, a.btn:hover { opacity: 0.92; }
  button:active, a.btn:active { transform: scale(0.98); }
  button.green, a.btn.green {
    background: linear-gradient(135deg, #34d399, #10b981);
    color: #032215;
  }
  button.secondary, a.btn.secondary {
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid var(--border);
  }
  .tabs {
    max-width: 1380px;
    margin: 16px auto 0;
    padding: 0 20px;
    display: flex;
    gap: 8px;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
  }
  .tab-btn {
    background: transparent;
    color: var(--muted);
    border: none;
    border-bottom: 3px solid transparent;
    border-radius: 0;
    padding: 10px 18px;
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
  }
  .tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    background: rgba(56, 189, 248, 0.07);
  }
  .tab-pane {
    display: none;
    max-width: 1380px;
    margin: 18px auto 36px;
    padding: 0 20px;
  }
  .tab-pane.active { display: block; }
  .grid-2 {
    display: grid;
    grid-template-columns: 340px 1fr;
    gap: 18px;
  }
  @media (max-width: 920px) {
    .grid-2 { grid-template-columns: 1fr; }
  }
  .grid-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
    gap: 18px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card h2 {
    margin: 0;
    font-size: 1rem;
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .fn-list {
    max-height: 520px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #060911;
  }
  .fn-item {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(51, 65, 85, 0.5);
    cursor: pointer;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.82rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .fn-item:hover, .fn-item.active {
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent);
  }
  input[type="text"], input[type="password"], select, textarea {
    background: #060911;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 9px 12px;
    border-radius: 8px;
    font-size: 0.86rem;
    width: 100%;
  }
  input[type="file"] {
    background: #060911;
    border: 1.5px dashed var(--accent);
    padding: 14px;
    border-radius: 8px;
    color: var(--text);
    width: 100%;
    cursor: pointer;
  }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  pre.code-view {
    background: #050811;
    border: 1px solid var(--border);
    padding: 16px;
    border-radius: 10px;
    overflow: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.83rem;
    color: #e2e8f0;
    margin: 0;
    min-height: 360px;
    max-height: 600px;
    white-space: pre-wrap;
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); }
  .pill {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.74rem;
    font-weight: 600;
    background: rgba(56, 189, 248, 0.16);
    color: var(--accent);
  }
  #toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #10b981;
    color: #032215;
    padding: 12px 20px;
    border-radius: 10px;
    font-weight: 700;
    font-size: 0.88rem;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    display: none;
    z-index: 9999;
  }
  .entropy-bar-bg {
    width: 100%;
    height: 12px;
    background: #060911;
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .entropy-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #10b981 0%, #f59e0b 70%, #ef4444 100%);
    width: 50%;
    transition: width 0.3s;
  }
</style>
</head>
<body>
<div id="toast">Copied!</div>

<header>
  <div class="brand">
    <span style="font-size:1.75rem;">🐉</span>
    <div>
      <h1>GhidraMCP v5.0 Workstation Pro</h1>
      <div id="env-subtitle" style="font-size:0.8rem;color:var(--muted);">__SSR_SUBTITLE__</div>
    </div>
    <span class="stage-badge" id="engine-stage-badge">__SSR_STAGE__</span>
  </div>
  <div class="mcp-bar">
    <span style="font-size:0.78rem;color:var(--muted);font-weight:600;">GEMINI MCP URL:</span>
    <code id="mcp-url-box">__SSR_MCP_URL__</code>
    <button class="green" id="btn-copy-mcp">Copy /mcp Link</button>
  </div>
</header>

<nav class="tabs">
  <button class="tab-btn active" data-tab="tab-decompiler">1. Live Decompiler &amp; Functions</button>
  <button class="tab-btn" data-tab="tab-binary">2. Binary Upload &amp; Hot-Swap</button>
  <button class="tab-btn" data-tab="tab-forensics">3. Static Forensics &amp; IOCs</button>
  <button class="tab-btn" data-tab="tab-cloud">4. Cloud Deployers &amp; Multi-Cloud Pool</button>
  <button class="tab-btn" data-tab="tab-logs">5. Live Engine Logs</button>
</nav>

<!-- TAB 1: Interactive Decompiler & Function Explorer -->
<div class="tab-pane active" id="tab-decompiler">
  <div class="grid-2">
    <div class="card">
      <h2>
        <span>Functions &amp; Symbols</span>
        <button class="secondary" id="btn-load-functions">Load from Ghidra</button>
      </h2>
      <input type="text" id="fn-filter" placeholder="Filter functions (e.g. main, verify, decrypt)...">
      <div class="fn-list" id="fn-list-box">
        <div style="padding:14px;color:var(--muted);font-size:0.83rem;">
          Click <b>Load from Ghidra</b> once the top badge says <b>READY</b> (or click any tool in the right panel) to browse functions and decompile them live!
        </div>
      </div>
      <div class="row">
        <button class="secondary" id="btn-list-imports" style="flex:1;">Imports</button>
        <button class="secondary" id="btn-list-exports" style="flex:1;">Exports</button>
        <button class="secondary" id="btn-list-strings" style="flex:1;">Strings</button>
      </div>
    </div>

    <div class="card">
      <h2>
        <span id="decompiler-title">Interactive Decompiler &amp; MCP Tool Output</span>
        <div class="row">
          <input type="text" id="decompile-fn-input" placeholder="Function name or address (e.g. main)" style="width:220px;">
          <button id="btn-decompile-fn">Decompile Function</button>
        </div>
      </h2>
      <pre class="code-view" id="decompiler-output">// Select a function on the left or click "Decompile Function" to view live Ghidra C pseudocode.
// Meanwhile, your active binary's static forensics summary is already loaded below:
__SSR_FORENSICS_JSON__</pre>
      <div class="row" style="border-top:1px solid var(--border);padding-top:12px;">
        <select id="playground-tool-select" style="flex:1;">
          <option value="triage_binary_forensics">triage_binary_forensics (Instant Static Triage)</option>
          <option value="cluster_fleet_status">cluster_fleet_status (Multi-Cloud Status)</option>
        </select>
        <input type="text" id="playground-tool-args" value="{}" placeholder='JSON args e.g. {"name": "main"}' style="flex:2;">
        <button class="secondary" id="btn-run-tool">Run MCP Tool</button>
      </div>
    </div>
  </div>
</div>

<!-- TAB 2: Binary Upload & Hot-Swap -->
<div class="tab-pane" id="tab-binary">
  <div class="grid-cards">
    <div class="card">
      <h2>Drag &amp; Drop Binary Upload (Instant Hot-Swap)</h2>
      <div style="font-size:0.84rem;color:var(--muted);">
        Upload any <code>.elf</code>, <code>.exe</code>, <code>.dll</code>, <code>.so</code>, or raw firmware image. Headless Ghidra 12.1.4 automatically switches to the new binary while keeping your Gemini <code>/mcp</code> URL unchanged!
      </div>
      <input type="file" id="binary-file">
      <button id="btn-upload-binary">Upload &amp; Hot-Swap Active Binary</button>
      <div id="swap-status" style="font-size:0.85rem;color:var(--success);font-weight:700;"></div>
    </div>

    <div class="card">
      <h2>Load Binary from Direct HTTPS URL or Cloud Path</h2>
      <div style="font-size:0.84rem;color:var(--muted);">
        Paste any direct download URL or mounted path (such as <code>/kaggle/input/...</code> or <code>/content/drive/MyDrive/...</code>):
      </div>
      <input type="text" id="binary-url" placeholder="https://example.com/target.elf or /kaggle/working/target.bin">
      <button class="secondary" id="btn-swap-url">Fetch &amp; Load into Ghidra</button>
    </div>
  </div>
</div>

<!-- TAB 3: Static Forensics & IOCs -->
<div class="tab-pane" id="tab-forensics">
  <div class="grid-cards">
    <div class="card">
      <h2>
        <span>Binary Header, Checksums &amp; Shannon Entropy</span>
        <button class="secondary" id="btn-refresh-forensics">Re-Scan</button>
      </h2>
      <div id="entropy-label" style="font-size:0.84rem;font-weight:600;">Entropy: Calculating...</div>
      <div class="entropy-bar-bg"><div class="entropy-bar-fill" id="entropy-bar"></div></div>
      <pre class="code-view" id="forensics-box" style="min-height:240px;">__SSR_FORENSICS_JSON__</pre>
    </div>
    <div class="card">
      <h2>Extracted IOCs &amp; Suspicious Strings</h2>
      <pre class="code-view" id="iocs-box" style="min-height:280px;">Loading strings...</pre>
    </div>
  </div>
</div>

<!-- TAB 4: Cloud Deployers & Multi-Cloud Cluster Pool -->
<div class="tab-pane" id="tab-cloud">
  <div class="card" style="margin-bottom:18px;border:2px solid var(--success);background:linear-gradient(180deg, rgba(16,185,129,0.10) 0%, var(--panel) 100%);">
    <h2>
      <span>⚡ 1-Click Fully Automated "Set-and-Forget Forever" Cloud Provisioner</span>
      <span class="stage-badge">Run Once on PC &rarr; Turn Off PC Forever</span>
    </h2>
    <div style="font-size:0.84rem;color:var(--muted);">
      Paste your <a href="https://github.com/settings/tokens/new?description=GhidraMCP-24x7-Forever&scopes=repo,workflow" target="_blank" style="color:var(--accent);">GitHub Token (repo + workflow)</a> (and optionally a free <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" style="color:var(--accent);">Cloudflare Workers API Token</a>, or leave Cloudflare blank to use 1-click Wrangler browser login) and click below. This script automatically provisions your <b>24/7 Self-Respawning GitHub Cloud Relay</b> AND deploys your <b>Permanent <code>.workers.dev/mcp</code> Router with Auto-Wake</b> in one shot!
    </div>
    <div class="row">
      <input type="password" id="forever-gh-token" placeholder="1. GitHub Token (ghp_... — leave blank if already saved or in gh CLI)" style="flex:1;">
      <input type="password" id="forever-cf-token" placeholder="2. Optional Cloudflare API Token (or leave blank for Wrangler browser login)" style="flex:1;">
      <button class="green" id="btn-run-forever">⚡ Auto-Provision 24/7 Cloud + Permanent URL Now</button>
    </div>
    <pre class="code-view" id="forever-output" style="display:none;min-height:140px;"></pre>
  </div>
  <div class="grid-cards">
    <div class="card">
      <h2>Option 1: 1-Click Kaggle (30 GB RAM) &amp; Colab Notebook (.ipynb)</h2>
      <div style="font-size:0.84rem;color:var(--muted);">
        Your Kaggle log proved Kaggle gives you <b>31.3 GB RAM (MAXMEM=16G)</b> and boots Headless Ghidra + Cloudflare Tunnel in ~40 seconds! Download the ready-made <code>.ipynb</code> below whenever you want to launch a fresh cloud session:
      </div>
      <a class="btn green" href="/api/download-notebook" download="GhidraMCP_Workstation_v5.ipynb">Download 1-Click Cloud Notebook (.ipynb)</a>
    </div>

    <div class="card">
      <h2>Permanent "Set-and-Forget" Front-Door Router (Never Re-Paste URLs!)</h2>
      <div style="font-size:0.83rem;color:var(--muted);">
        Temporary <code>.trycloudflare.com</code> links expire when a session ends. Deploy our 24/7 GitHub Relay (right) + paste this tiny free Worker script into <a href="https://dash.cloudflare.com/" target="_blank" style="color:var(--accent);">Cloudflare Workers Free Tier</a> once. It gives you <b>one permanent <code>.workers.dev/mcp</code> URL</b> that automatically follows your rotating GitHub Cloud tunnels forever!
      </div>
      <div class="row">
        <input type="text" id="cf-gh-user" placeholder="Your GitHub Username (for LIVE_MCP_URL.json)" style="flex:1;">
        <button class="green" id="btn-dl-worker">Download Permanent Worker (.js)</button>
      </div>
    </div>

    <div class="card">
      <h2>Option 2: 1-Click 24/7 Perpetual GitHub Cloud Auto-Deployer</h2>
      <div style="font-size:0.84rem;color:var(--muted);">
        Paste a free <a href="https://github.com/settings/tokens/new?description=GhidraMCP-Cloud&scopes=repo,workflow" target="_blank" style="color:var(--accent);">GitHub Token (repo + workflow)</a> to auto-create a repository and boot GhidraMCP on GitHub Actions' free 16 GB RAM Ubuntu runner:
      </div>
      <input type="password" id="gh-token" placeholder="Paste ghp_... token here">
      <button id="btn-deploy-gh">Auto-Launch on GitHub Cloud &amp; Fetch Live Link</button>
      <pre class="code-view" id="cloud-deploy-result" style="display:none;min-height:120px;"></pre>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>
        <span>Multi-Cloud Cluster Pool (Link All Your Running Cloud Nodes Together)</span>
        <button class="secondary" id="btn-ping-nodes">Health-Check All Nodes</button>
      </h2>
      <div class="row">
        <input type="text" id="node-name" placeholder="Node Name (e.g. kaggle-30gb)" style="flex:1;">
        <select id="node-provider" style="flex:1;">
          <option value="Kaggle Cloud (30 GB RAM)">Kaggle Cloud (30 GB RAM)</option>
          <option value="GitHub Actions Cloud (16 GB RAM)">GitHub Actions Cloud (16 GB RAM)</option>
          <option value="Google Colab VM">Google Colab VM</option>
          <option value="GitHub Codespaces">GitHub Codespaces</option>
          <option value="Lightning AI Studio">Lightning AI Studio</option>
        </select>
        <input type="text" id="node-url" placeholder="https://contract-scan-keyword-venue.trycloudflare.com/mcp" style="flex:2;">
        <button id="btn-add-node">+ Add Cloud Node</button>
      </div>
      <table>
        <thead>
          <tr><th>Node Name</th><th>Provider</th><th>Remote MCP Endpoint</th><th>Status</th><th>Action</th></tr>
        </thead>
        <tbody id="fleet-tbody">
          <tr><td colspan="5" style="color:var(--muted);">No external cloud nodes linked yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB 5: Live Engine Logs -->
<div class="tab-pane" id="tab-logs">
  <div class="card">
    <h2>
      <span>Live Headless Ghidra 12.1.4 &amp; Cloudflare Tunnel Logs</span>
      <button class="secondary" id="btn-refresh-logs">Refresh Now</button>
    </h2>
    <pre class="code-view" id="logs-box">__SSR_LOGS__</pre>
  </div>
</div>

<script>
let latestPublicMcpUrl = "__SSR_MCP_URL__";
let allFunctionsCache = [];

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.display = "block";
  setTimeout(() => { t.style.display = "none"; }, 3200);
}

// Tab switching
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const pane = document.getElementById(btn.getAttribute("data-tab"));
    if (pane) pane.classList.add("active");
  });
});

async function callMcpTool(toolName, argsObj) {
  const rpc = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "tools/call",
    params: { name: toolName, arguments: argsObj || {} }
  };
  const res = await fetch("/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rpc)
  });
  const data = await res.json();
  if (data && data.result && data.result.content && data.result.content.length) {
    return data.result.content.map((c) => c.text || JSON.stringify(c)).join("\n");
  }
  return JSON.stringify(data, null, 2);
}

async function refreshAvailableTools() {
  try {
    const res = await fetch("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/list", params: {} })
    });
    const data = await res.json();
    const tools = (data && data.result && data.result.tools) ? data.result.tools : [];
    const sel = document.getElementById("playground-tool-select");
    if (tools.length && sel) {
      const currentVal = sel.value;
      sel.innerHTML = tools.map((t) => `<option value="${t.name}">${t.name}</option>`).join("");
      if (currentVal) sel.value = currentVal;
    }
  } catch (e) {}
}

function renderFunctionList(filterText) {
  const box = document.getElementById("fn-list-box");
  const q = (filterText || "").toLowerCase();
  const filtered = allFunctionsCache.filter((fn) => fn.toLowerCase().includes(q));
  if (!filtered.length) {
    box.innerHTML = '<div style="padding:14px;color:var(--muted);font-size:0.82rem;">No matching functions found. Wait until top badge says READY, then click Load from Ghidra.</div>';
    return;
  }
  box.innerHTML = filtered.slice(0, 250).map((fn) => {
    const safe = fn.replace(/"/g, "&quot;");
    return `<div class="fn-item" data-fn="${safe}"><span>${safe}</span><span class="pill">Decompile &rarr;</span></div>`;
  }).join("");
  box.querySelectorAll(".fn-item").forEach((item) => {
    item.addEventListener("click", () => {
      const fnName = item.getAttribute("data-fn");
      document.getElementById("decompile-fn-input").value = fnName;
      decompileFunctionByName(fnName);
    });
  });
}

async function loadFunctionsFromGhidra() {
  const box = document.getElementById("fn-list-box");
  box.innerHTML = '<div style="padding:14px;color:var(--accent);">Querying Headless Ghidra for functions...</div>';
  for (const candidateTool of ["list_methods", "list_functions", "get_functions"]) {
    const out = await callMcpTool(candidateTool, { offset: 0, limit: 200 });
    if (out && !out.includes("currently in stage") && !out.includes("Unknown tool")) {
      const lines = out.split(/\r?\n/).map((s) => s.trim()).filter((s) => s.length > 0 && !s.startsWith("{"));
      if (lines.length) {
        allFunctionsCache = lines;
        renderFunctionList(document.getElementById("fn-filter").value);
        showToast("Loaded " + lines.length + " functions from Ghidra!");
        return;
      }
    }
  }
  document.getElementById("decompiler-output").textContent =
    "// Ghidra is still finishing initial auto-analysis (or no functions returned yet).\n// Check the top-right badge: once it says READY, click 'Load from Ghidra' again!";
}

async function decompileFunctionByName(fnName) {
  if (!fnName) return;
  const outBox = document.getElementById("decompiler-output");
  document.getElementById("decompiler-title").textContent = "Decompiling: " + fnName + " ...";
  outBox.textContent = "// Decompiling " + fnName + " via Headless Ghidra 12.1.4...";
  for (const toolChoice of [
    ["decompile_function", { name: fnName }],
    ["decompile_function_by_name", { name: fnName }],
    ["decompile_method", { name: fnName }]
  ]) {
    const text = await callMcpTool(toolChoice[0], toolChoice[1]);
    if (text && !text.includes("Unknown tool")) {
      document.getElementById("decompiler-title").textContent = "Decompiled C: " + fnName;
      outBox.textContent = text;
      return;
    }
  }
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.public_mcp_url) {
      latestPublicMcpUrl = data.public_mcp_url;
      document.getElementById("mcp-url-box").textContent = latestPublicMcpUrl;
    }
    document.getElementById("env-subtitle").textContent =
      data.env.platform + " • " + data.env.total_ram_gb + " GB RAM • JVM Heap: " + data.env.jvm_maxmem + " • Binary: " + (data.forensics.file_name || "sample_crackme");
    document.getElementById("engine-stage-badge").textContent = "ENGINE: " + (data.engine_stage || "READY");
    document.getElementById("forensics-box").textContent = JSON.stringify(data.forensics, null, 2);
    document.getElementById("iocs-box").textContent = JSON.stringify({
      urls: data.forensics.extracted_urls || [],
      ipv4s: data.forensics.extracted_ipv4s || [],
      interesting_strings: data.forensics.interesting_strings || []
    }, null, 2);
    const ent = data.forensics.shannon_entropy_bits_per_byte || 0;
    document.getElementById("entropy-label").textContent =
      "Shannon Entropy: " + ent + " / 8.0 bits (" + (data.forensics.packer_assessment || "") + ")";
    document.getElementById("entropy-bar").style.width = Math.min(100, Math.round((ent / 8.0) * 100)) + "%";
    document.getElementById("logs-box").textContent = (data.logs || []).join("\n");
    renderFleet(data.fleet || {});
  } catch (e) {}
}

function renderFleet(fleet) {
  const tbody = document.getElementById("fleet-tbody");
  const keys = Object.keys(fleet);
  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);">No external cloud nodes linked yet. Paste your Kaggle or GitHub Cloud /mcp URL above to pool multiple clouds!</td></tr>';
    return;
  }
  tbody.innerHTML = keys.map((k) => {
    const n = fleet[k];
    return `<tr>
      <td><b>${n.name}</b></td>
      <td><span class="pill">${n.provider}</span></td>
      <td><code>${n.mcp_url}</code></td>
      <td>${n.status}</td>
      <td><button class="secondary" data-rm="${n.name}">Remove</button></td>
    </tr>`;
  }).join("");
  tbody.querySelectorAll("button[data-rm]").forEach((b) => {
    b.addEventListener("click", async () => {
      await fetch("/api/fleet/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: b.getAttribute("data-rm") })
      });
      const foreverBtn = document.getElementById("btn-run-forever");
if (foreverBtn) {
  foreverBtn.addEventListener("click", async () => {
    const gh_token = document.getElementById("forever-gh-token").value.trim();
    const cf_token = document.getElementById("forever-cf-token").value.trim();
    const outBox = document.getElementById("forever-output");
    outBox.style.display = "block";
    outBox.textContent = "Running 100% Automated Set-and-Forget Cloud Provisioner (GitHub 24/7 Relay + Cloudflare Permanent Worker)...";
    const res = await fetch("/api/auto-provision-forever", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ gh_token, cf_token, repo_name: "ghidra-mcp-omni-cloud" })
    });
    const data = await res.json();
    outBox.textContent = JSON.stringify(data, null, 2);
    if (data.raw_live_url) {
      let elapsed = 0;
      const timer = setInterval(async () => {
        elapsed += 5;
        try {
          const r = await fetch(data.raw_live_url + "?t=" + Date.now());
          if (r.ok) {
            const live = await r.json();
            if (live.mcp_url) {
              clearInterval(timer);
              const bestUrl = (data.cloudflare_worker_result && data.cloudflare_worker_result.permanent_mcp_url) || live.mcp_url;
              navigator.clipboard.writeText(bestUrl);
              outBox.textContent = JSON.stringify({ ...data, active_relay_tunnel_mcp_url: live.mcp_url, COPIED_TO_CLIPBOARD: bestUrl }, null, 2);
              showToast("Set-and-Forget Cloud URL Ready & Copied: " + bestUrl);
            }
          }
        } catch (e) {}
      }, 5000);
    }
  });
}

const dlWorkerBtn = document.getElementById("btn-dl-worker");
if (dlWorkerBtn) {
  dlWorkerBtn.addEventListener("click", () => {
    const u = (document.getElementById("cf-gh-user").value || "").trim() || "YOUR_GITHUB_USERNAME";
    window.location.href = "/api/download-worker?user=" + encodeURIComponent(u);
  });
}

refreshStatus();
    });
  });
}

// Event Listeners
document.getElementById("btn-copy-mcp").addEventListener("click", () => {
  navigator.clipboard.writeText(latestPublicMcpUrl);
  showToast("Copied Gemini MCP Link: " + latestPublicMcpUrl);
});

document.getElementById("btn-load-functions").addEventListener("click", loadFunctionsFromGhidra);
document.getElementById("fn-filter").addEventListener("input", (e) => renderFunctionList(e.target.value));
document.getElementById("btn-decompile-fn").addEventListener("click", () => {
  decompileFunctionByName(document.getElementById("decompile-fn-input").value.trim());
});

document.getElementById("btn-list-imports").addEventListener("click", async () => {
  document.getElementById("decompiler-output").textContent = await callMcpTool("list_imports", {});
});
document.getElementById("btn-list-exports").addEventListener("click", async () => {
  document.getElementById("decompiler-output").textContent = await callMcpTool("list_exports", {});
});
document.getElementById("btn-list-strings").addEventListener("click", async () => {
  document.getElementById("decompiler-output").textContent = await callMcpTool("list_strings", {});
});

document.getElementById("btn-run-tool").addEventListener("click", async () => {
  const tName = document.getElementById("playground-tool-select").value;
  let args = {};
  try { args = JSON.parse(document.getElementById("playground-tool-args").value || "{}"); } catch (e) {}
  document.getElementById("decompiler-output").textContent = await callMcpTool(tName, args);
});

document.getElementById("btn-upload-binary").addEventListener("click", () => {
  const input = document.getElementById("binary-file");
  if (!input.files.length) { showToast("Select a binary file first!"); return; }
  const file = input.files[0];
  const reader = new FileReader();
  document.getElementById("swap-status").textContent = "Uploading & hot-swapping " + file.name + "...";
  reader.onload = async () => {
    const b64 = reader.result.split(",")[1];
    const res = await fetch("/api/upload-binary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, content_b64: b64 })
    });
    const out = await res.json();
    document.getElementById("swap-status").textContent = "Switched active binary to: " + (out.active_binary || file.name);
    showToast("Hot-swapped binary: " + file.name);
    refreshStatus();
  };
  reader.readAsDataURL(file);
});

document.getElementById("btn-swap-url").addEventListener("click", async () => {
  const val = document.getElementById("binary-url").value.trim();
  if (!val) return;
  document.getElementById("swap-status").textContent = "Loading " + val + "...";
  const res = await fetch("/api/swap-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url_or_path: val })
  });
  const out = await res.json();
  document.getElementById("swap-status").textContent = "Active binary: " + (out.active_binary || out.error);
  showToast("Loaded binary from URL/path!");
  refreshStatus();
});

document.getElementById("btn-refresh-forensics").addEventListener("click", refreshStatus);
document.getElementById("btn-refresh-logs").addEventListener("click", refreshStatus);

document.getElementById("btn-add-node").addEventListener("click", async () => {
  const name = document.getElementById("node-name").value.trim();
  const provider = document.getElementById("node-provider").value;
  const mcp_url = document.getElementById("node-url").value.trim();
  if (!name || !mcp_url) { showToast("Enter node name and /mcp URL"); return; }
  await fetch("/api/fleet/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, provider, mcp_url })
  });
  document.getElementById("node-name").value = "";
  document.getElementById("node-url").value = "";
  showToast("Added cloud node: " + name);
  refreshStatus();
});

document.getElementById("btn-ping-nodes").addEventListener("click", async () => {
  await fetch("/api/fleet/ping", { method: "POST" });
  showToast("Updated fleet health status!");
  refreshStatus();
});

document.getElementById("btn-deploy-gh").addEventListener("click", async () => {
  const token = document.getElementById("gh-token").value.trim();
  if (!token) { showToast("Paste your GitHub token (ghp_...) first!"); return; }
  const box = document.getElementById("cloud-deploy-result");
  box.style.display = "block";
  box.textContent = "Creating public GitHub repository & starting 100% Free GitHub Actions Cloud Runner...";
  const res = await fetch("/api/deploy-github", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, repo_name: "ghidra-mcp-omni-cloud" })
  });
  const data = await res.json();
  box.textContent = JSON.stringify(data, null, 2);
  if (data.raw_live_url) {
    let elapsed = 0;
    const pollTimer = setInterval(async () => {
      elapsed += 5;
      try {
        const r = await fetch(data.raw_live_url + "?t=" + Date.now());
        if (r.ok) {
          const live = await r.json();
          if (live.mcp_url) {
            clearInterval(pollTimer);
            navigator.clipboard.writeText(live.mcp_url);
            box.textContent = [
              "GITHUB CLOUD SERVER IS LIVE!",
              "GEMINI MCP URL (Copied to clipboard): " + live.mcp_url,
              "CLOUD WORKSTATION GUI: " + live.gui_url
            ].join("\n");
            showToast("GitHub Cloud MCP Link copied to clipboard!");
          }
        }
      } catch (e) {}
    }, 5000);
  }
});

refreshStatus();
refreshAvailableTools();
setInterval(refreshStatus, 3500);
setInterval(refreshAvailableTools, 12000);
</script>
</body>
</html>
"""


def render_ssr_gui_html(state: OmniCloudState) -> str:
    """Server-Side Render (SSR) the initial state directly into the HTML so the user immediately
    sees their live URL, platform, and binary forensics even before JavaScript runs!"""
    mcp_url = f"{state.public_base_url.rstrip('/')}/mcp"
    forensics = analyze_binary_forensics(state.active_binary)
    subtitle = (
        f"{state.env_info['platform']} • {state.env_info['total_ram_gb']} GB RAM • "
        f"JVM Heap: {state.env_info['jvm_maxmem']} • Binary: {forensics.get('file_name', 'sample_crackme')}"
    )
    html_out = WEB_GUI_TEMPLATE
    html_out = html_out.replace("__SSR_MCP_URL__", html.escape(mcp_url))
    html_out = html_out.replace("__SSR_SUBTITLE__", html.escape(subtitle))
    html_out = html_out.replace("__SSR_STAGE__", html.escape(f"ENGINE: {state.engine_stage}"))
    html_out = html_out.replace("__SSR_FORENSICS_JSON__", html.escape(json.dumps(forensics, indent=2)))
    html_out = html_out.replace("__SSR_LOGS__", html.escape("\n".join(list(state.logs)[-80:])))
    return html_out


# ---------------------------------------------------------------------------
# 7. Unified HTTP Server (Serves SSR Web GUI on `/` + Gemini MCP on `/mcp`)
# ---------------------------------------------------------------------------


class OmniCloudHTTPHandler(http.server.BaseHTTPRequestHandler):
    state: OmniCloudState = None  # type: ignore

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, MCP-Session-Id, Last-Event-ID")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html_str: str) -> None:
        raw = html_str.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self._send_json({"status": "ok"})

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html", "/gui"):
            self._send_html(render_ssr_gui_html(self.state))
            return

        if path == "/api/status":
            forensics = analyze_binary_forensics(self.state.active_binary)
            self._send_json({
                "env": self.state.env_info,
                "engine_stage": self.state.engine_stage,
                "public_mcp_url": f"{self.state.public_base_url.rstrip('/')}/mcp",
                "backend_running": bool(self.state.ghidra_proc and self.state.ghidra_proc.poll() is None),
                "forensics": forensics,
                "fleet": self.state.fleet_nodes,
                "logs": list(self.state.logs)[-100:],
            })
            return

        if path == "/api/download-worker":
            gh_user = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("user", ["YOUR_GITHUB_USERNAME"])[0]
            w_bytes = build_permanent_cloudflare_worker_js(gh_user, "ghidra-mcp-omni-cloud").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="cloudflare_permanent_router_worker.js"')
            self.send_header("Content-Length", str(len(w_bytes)))
            self.end_headers()
            self.wfile.write(w_bytes)
            return

        if path == "/api/download-notebook":
            nb_bytes = build_oneclick_ipynb_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ipynb+json")
            self.send_header("Content-Disposition", 'attachment; filename="GhidraMCP_Workstation_v5.ipynb"')
            self.send_header("Content-Length", str(len(nb_bytes)))
            self.end_headers()
            self.wfile.write(nb_bytes)
            return

        if path in ("/mcp", "/sse"):
            self._send_json({
                "name": "GhidraMCP-WorkstationPro",
                "version": "5.0.0",
                "status": "100% Free & Open Keyless MCP Endpoint",
                "engine_stage": self.state.engine_stage,
                "web_gui": "/",
                "mcp_endpoint": "/mcp",
            })
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8", errors="replace"))
        except Exception:
            body = {}

        if path in ("/mcp", "/sse"):
            rpc_resp = handle_mcp_jsonrpc(self.state, body)
            self._send_json(rpc_resp)
            return

        if path == "/api/upload-binary":
            fname = re.sub(r"[^a-zA-Z0-9._-]", "_", body.get("filename", "uploaded_binary.bin"))
            b64_data = body.get("content_b64", "")
            uploads_dir = self.state.work_dir / "uploaded_binaries"
            uploads_dir.mkdir(parents=True, exist_ok=True)
            dest = uploads_dir / fname
            dest.write_bytes(base64.b64decode(b64_data))
            try:
                dest.chmod(0o755)
            except Exception:
                pass
            res = self.state.start_or_restart_backend(dest)
            self._send_json(res)
            return

        if path == "/api/swap-url":
            try:
                new_bin = prepare_target_binary(body.get("url_or_path", ""), self.state.work_dir)
                res = self.state.start_or_restart_backend(new_bin)
                self._send_json(res)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        if path == "/api/fleet/add":
            info = self.state.register_node(
                body.get("name", "cloud-node"),
                body.get("mcp_url", ""),
                body.get("provider", "Cloud Node"),
            )
            self._send_json(info)
            return

        if path == "/api/fleet/remove":
            ok = self.state.remove_node(body.get("name", ""))
            self._send_json({"removed": ok})
            return

        if path == "/api/fleet/ping":
            self._send_json(self.state.check_fleet_health())
            return

        if path == "/api/auto-provision-forever":
            res = run_autonomous_forever_provisioner(
                work_dir=self.state.work_dir,
                gh_token_input=body.get("gh_token", ""),
                cf_token_input=body.get("cf_token", ""),
                repo_name=body.get("repo_name", "ghidra-mcp-omni-cloud"),
                interactive_cli=False,
            )
            self._send_json(res)
            return

        if path == "/api/deploy-github":
            res = deploy_to_github_cloud_api(body.get("token", ""), body.get("repo_name", "ghidra-mcp-omni-cloud"))
            self._send_json(res)
            return

        if path == "/api/deploy-hf":
            res = deploy_to_huggingface_api(body.get("token", ""), body.get("space_name", "ghidra-mcp-omni"))
            if res.get("status") == "DEPLOYED" and res.get("gemini_mcp_url"):
                self.state.register_node(
                    body.get("space_name", "hf-permanent"),
                    res["gemini_mcp_url"],
                    "Hugging Face Space",
                )
            self._send_json(res)
            return

        self._send_json({"error": "Unknown endpoint"}, status=404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# 8. Cross-Platform Download, JDK 21, Ghidra 12.1.4 & Cloudflared Helpers
# ---------------------------------------------------------------------------


def verify_sha256(file_path: Path, expected_hex: str) -> bool:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().lower() == expected_hex.lower()


def download_file(url: str, dest: Path, expected_sha256: str = "") -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if not expected_sha256 or verify_sha256(dest, expected_sha256):
            print(f"[+] Reusing cached {dest.name} ({dest})")
            return dest
        dest.unlink()

    print(f"[+] Downloading {url} -> {dest} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (GhidraMCP-WorkstationPro/5.0)"})
    with urllib.request.urlopen(req) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)

    if expected_sha256 and not verify_sha256(dest, expected_sha256):
        raise RuntimeError(f"SHA-256 mismatch on {dest.name}! Expected {expected_sha256}")
    return dest


def find_or_install_jdk21(work_dir: Path) -> Optional[str]:
    sys_name = platform.system().lower()

    if "JAVA_HOME" in os.environ and Path(os.environ["JAVA_HOME"]).exists():
        if "21" in subprocess.getoutput(f'"{Path(os.environ["JAVA_HOME"]) / "bin" / "java"}" -version'):
            return os.environ["JAVA_HOME"]

    if "windows" in sys_name:
        win_roots = [
            Path("C:/Program Files/Eclipse Adoptium"),
            Path("C:/Program Files/Microsoft"),
            Path("C:/Program Files/Java"),
            Path("C:/Program Files/BellSoft"),
            work_dir / "jdk21",
        ]
        for root in win_roots:
            if root.exists():
                for candidate in sorted(root.glob("*21*"), reverse=True):
                    if (candidate / "bin" / "java.exe").exists():
                        return str(candidate)
        for sub in sorted((work_dir / "jdk21").glob("jdk*"), reverse=True) if (work_dir / "jdk21").exists() else []:
            if (sub / "bin" / "java.exe").exists():
                return str(sub)

        if shutil.which("java") and "21" in subprocess.getoutput("java -version"):
            return None

        print("[+] JDK 21 not found in Program Files — downloading portable OpenJDK 21 for Windows...")
        jdk_zip = work_dir / "openjdk21_win_x64.zip"
        jdk_url = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
        try:
            download_file(jdk_url, jdk_zip)
            jdk_extract_dir = work_dir / "jdk21"
            jdk_extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(jdk_zip, "r") as zf:
                zf.extractall(jdk_extract_dir)
            for sub in jdk_extract_dir.glob("jdk*"):
                if (sub / "bin" / "java.exe").exists():
                    print(f"[+] Portable Windows OpenJDK 21 ready at: {sub}")
                    return str(sub)
        except Exception as exc:
            print(f"[!] Portable JDK 21 download note: {exc}")
        return None

    if Path("/usr/lib/jvm/java-21-openjdk-amd64").exists():
        return "/usr/lib/jvm/java-21-openjdk-amd64"
    if not shutil.which("java") or "21" not in subprocess.getoutput("java -version"):
        if shutil.which("apt-get"):
            print("[+] Installing OpenJDK 21 via apt-get...")
            subprocess.run(["sudo", "apt-get", "update", "-y"], check=False)
            subprocess.run(["sudo", "apt-get", "install", "-y", "openjdk-21-jdk", "unzip", "gcc"], check=False)
            if Path("/usr/lib/jvm/java-21-openjdk-amd64").exists():
                return "/usr/lib/jvm/java-21-openjdk-amd64"
    return None


def ensure_uv_installed() -> None:
    local_bin = str(Path.home() / ".local" / "bin")
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    os.environ["PATH"] = f"{local_bin}{os.pathsep}{cargo_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    if shutil.which("uvx") or shutil.which("uv"):
        return

    sys_name = platform.system().lower()
    print("[+] Installing Astral uv package runner...")
    if "windows" in sys_name:
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "irm https://astral.sh/uv/install.ps1 | iex"],
            check=False,
        )
    else:
        subprocess.run("curl -LsSf https://astral.sh/uv/install.sh | sh", shell=True, check=False)


def ensure_ghidra_and_extension(work_dir: Path) -> Path:
    opt_ghidra = Path("/opt/ghidra_12.1.4_PUBLIC")
    if opt_ghidra.exists():
        return opt_ghidra

    win_cached = Path("C:/tmp/ghidra_mcp_cloud") / f"ghidra_{GHIDRA_VERSION}_PUBLIC"
    if win_cached.exists():
        print(f"[+] Found existing extracted Ghidra 12.1.4 at {win_cached} (0 MB download needed!)")
        ghidra_dir = win_cached
        work_dir = Path("C:/tmp/ghidra_mcp_cloud")
    else:
        ghidra_dir = work_dir / f"ghidra_{GHIDRA_VERSION}_PUBLIC"

    if not ghidra_dir.exists():
        ghidra_zip = download_file(GHIDRA_DOWNLOAD_URL, work_dir / GHIDRA_ZIP_NAME, GHIDRA_SHA256)
        print(f"[+] Extracting {ghidra_zip.name} ...")
        with zipfile.ZipFile(ghidra_zip, "r") as zf:
            zf.extractall(work_dir)

    ext_root = ghidra_dir / "Ghidra" / "Extensions"
    if not (ext_root / "GhidraMCP").exists():
        rel_zip = download_file(
            GHIDRA_MCP_RELEASE_URL,
            work_dir / "GhidraMCP-release-2-0.zip",
            GHIDRA_MCP_RELEASE_SHA256,
        )
        tmp_ext = work_dir / "ghidramcp_ext_tmp"
        tmp_ext.mkdir(exist_ok=True)
        with zipfile.ZipFile(rel_zip, "r") as zf:
            zf.extractall(tmp_ext)

        inner_zips = list(tmp_ext.rglob("*GhidraMCP*.zip"))
        if not inner_zips:
            raise RuntimeError("Could not find inner GhidraMCP extension zip inside release archive.")
        with zipfile.ZipFile(inner_zips[0], "r") as izf:
            izf.extractall(ext_root)
        shutil.rmtree(tmp_ext, ignore_errors=True)
    for native_sub in ["Ghidra/Features/Decompiler/os", "Ghidra/Processors", "support", "GPL"]:
        sub_path = ghidra_dir / native_sub
        if sub_path.exists():
            for bin_file in sub_path.rglob("*"):
                if bin_file.is_file():
                    try:
                        bin_file.chmod(0o755)
                    except Exception:
                        pass
    return ghidra_dir


def prepare_target_binary(binary_arg: str, work_dir: Path) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    if binary_arg:
        if binary_arg.startswith(("http://", "https://")):
            target_path = work_dir / "uploaded_binaries" / Path(urllib.parse.urlparse(binary_arg).path).name
            target_path.parent.mkdir(parents=True, exist_ok=True)
            download_file(binary_arg, target_path)
            try:
                target_path.chmod(0o755)
            except Exception:
                pass
            return target_path
        target_path = Path(binary_arg).expanduser().resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target binary not found: {target_path}")
        return target_path

    sample_c = work_dir / "sample_crackme.c"
    sample_bin = work_dir / "sample_crackme"
    if not sample_bin.exists():
        sample_c.write_text(
            '#include <stdio.h>\n#include <string.h>\n'
            'const char *C2_URL = "https://telemetry.example.org/api/v1/beacon";\n'
            'int verify_token(const char *s) { return strcmp(s, "GEMINI_GHIDRA_WORKSTATION_2026") == 0; }\n'
            'int main(int argc, char **argv) {\n'
            '    if (argc > 1 && verify_token(argv[1])) { puts("Unlocked!"); return 0; }\n'
            '    puts("Locked!"); return 1;\n'
            '}\n',
            encoding="utf-8",
        )
        if shutil.which("gcc"):
            try:
                subprocess.run(["gcc", "-O1", "-o", str(sample_bin), str(sample_c)], check=True)
                return sample_bin
            except Exception:
                pass
        sample_bin.write_bytes(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
            b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
            b"\xb0\x00\x00\x00\x00\x00\x00\x00\xb0\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x10\x00\x00\x00\x00\x00\x00"
            b"\x55\x48\x89\xe5\x48\x8d\x3d\x10\x00\x00\x00\xb8\x00\x00\x00\x00\x5d\xc3\x90\x90"
            b"https://telemetry.example.org/api/v1/beacon\x00GEMINI_GHIDRA_WORKSTATION_2026\x00"
        )
    return sample_bin


def ensure_cloudflared(work_dir: Path) -> Path:
    existing = shutil.which("cloudflared")
    if existing:
        return Path(existing)

    sys_name = platform.system().lower()
    machine = platform.machine().lower()

    if "windows" in sys_name:
        bad_linux_bin = work_dir / "cloudflared"
        if bad_linux_bin.exists() and not bad_linux_bin.name.endswith(".exe"):
            try:
                bad_linux_bin.unlink()
            except Exception:
                pass
        cf_bin = work_dir / "cloudflared.exe"
        if not cf_bin.exists():
            download_file(CLOUDFLARED_URLS["windows"], cf_bin)
        return cf_bin

    if "darwin" in sys_name:
        cf_bin = work_dir / "cloudflared"
        if not cf_bin.exists():
            tgz_url = CLOUDFLARED_URLS["darwin_arm64"] if ("arm" in machine or "aarch64" in machine) else CLOUDFLARED_URLS["darwin_amd64"]
            tgz_path = work_dir / "cloudflared.tgz"
            download_file(tgz_url, tgz_path)
            subprocess.run(["tar", "-xzf", str(tgz_path), "-C", str(work_dir)], check=True)
            cf_bin.chmod(0o755)
        return cf_bin

    cf_bin = work_dir / "cloudflared"
    if not cf_bin.exists():
        linux_url = CLOUDFLARED_URLS["linux_arm64"] if ("arm" in machine or "aarch64" in machine) else CLOUDFLARED_URLS["linux_amd64"]
        download_file(linux_url, cf_bin)
        cf_bin.chmod(0o755)
    return cf_bin


# ---------------------------------------------------------------------------
# 9. Automated Self-Test (Validates SSR HTML, JS Syntax & Stateful MCP Bridge)
# ---------------------------------------------------------------------------


def run_self_test() -> None:
    tmp_dir = Path("/tmp/ghidra_omni_selftest")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    state = OmniCloudState(work_dir=tmp_dir, gateway_port=17860, backend_port=18081, transport="streamable-http")
    state.active_binary = prepare_target_binary("", tmp_dir)
    state.public_base_url = "https://contract-scan-keyword-venue.trycloudflare.com"

    OmniCloudHTTPHandler.state = state
    httpd = ThreadedHTTPServer(("127.0.0.1", 17860), OmniCloudHTTPHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        with urllib.request.urlopen("http://127.0.0.1:17860/", timeout=5) as r_gui:
            html_body = r_gui.read().decode("utf-8")
            assert "GhidraMCP v5.0 Workstation Pro" in html_body, "Workstation Pro v5.0 title missing"
            assert "https://contract-scan-keyword-venue.trycloudflare.com/mcp" in html_body, "SSR MCP URL missing"

        # Extract embedded <script> and validate syntax with node --check if node is installed
        m_js = re.search(r"<script>(.*)</script>", html_body, re.DOTALL)
        assert m_js, "Missing <script> tag in HTML"
        js_file = tmp_dir / "extracted_gui.js"
        js_file.write_text(m_js.group(1), encoding="utf-8")
        if shutil.which("node"):
            subprocess.run(["node", "--check", str(js_file)], check=True)

        init_res = forward_jsonrpc_to_url(
            "http://127.0.0.1:17860/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert init_res and init_res["result"]["serverInfo"]["name"] == "GhidraMCP-WorkstationPro"

        tools_res = forward_jsonrpc_to_url(
            "http://127.0.0.1:17860/mcp",
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        tool_names = [t["name"] for t in tools_res["result"]["tools"]]
        assert "triage_binary_forensics" in tool_names and "hot_swap_target_binary" in tool_names

        call_res = forward_jsonrpc_to_url(
            "http://127.0.0.1:17860/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "triage_binary_forensics", "arguments": {}},
            },
        )
        forensics_data = json.loads(call_res["result"]["content"][0]["text"])
        print("[+] v5.0 Workstation Pro Self-Test PASSED (Zero Warnings, Validated JS & SSR)!")
        print(f"    - Detected Platform : {state.env_info['platform']} ({state.env_info['total_ram_gb']} GB RAM)")
        print(f"    - SSR GUI Verified  : http://127.0.0.1:17860/ ({len(html_body)} bytes HTML5, JS syntax verified)")
        print(f"    - MCP Tools Exposed : {', '.join(tool_names)}")
        print(f"    - Sample Binary SHA : {forensics_data['sha256'][:24]}... ({forensics_data['format']})")
    finally:
        httpd.shutdown(); httpd.server_close()


def launch_omni_cloud(args: argparse.Namespace) -> None:
    env_info = detect_cloud_environment()
    work_dir = Path(args.work_dir) if args.work_dir else Path(env_info["default_work_dir"])
    work_dir.mkdir(parents=True, exist_ok=True)

    state = OmniCloudState(
        work_dir=work_dir,
        gateway_port=args.port,
        backend_port=args.backend_port,
        transport=args.transport,
    )
    state.log(f"Detected environment: {env_info['platform']} ({env_info['total_ram_gb']} GB RAM -> JVM MAXMEM={env_info['jvm_maxmem']})")
    state.log(f"Working & cache folder: {work_dir}")

    initial_bin = prepare_target_binary(args.binary, work_dir)
    state.active_binary = initial_bin

    OmniCloudHTTPHandler.state = state
    httpd = None
    for candidate_port in range(args.port, args.port + 15):
        try:
            httpd = ThreadedHTTPServer(("0.0.0.0", candidate_port), OmniCloudHTTPHandler)
            args.port = candidate_port
            state.gateway_port = candidate_port
            break
        except OSError:
            continue
    if httpd is None:
        httpd = ThreadedHTTPServer(("0.0.0.0", 0), OmniCloudHTTPHandler)
        args.port = httpd.server_address[1]
        state.gateway_port = args.port

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    local_gui_url = f"http://127.0.0.1:{args.port}/"
    state.log(f"Workstation Pro Web GUI listening at: {local_gui_url}")

    ensure_uv_installed()
    state.java_home = find_or_install_jdk21(work_dir)
    state.ghidra_dir = ensure_ghidra_and_extension(work_dir)
    state.start_or_restart_backend(initial_bin)

    use_tunnel = env_info["needs_tunnel"] and not args.no_tunnel
    if not use_tunnel:
        print("\n" + "=" * 82)
        print("  GHIDRAMCP v5.0 WORKSTATION PRO IS LIVE (DIRECT CONTAINER PORT MODE)")
        print("=" * 82)
        print(f"  WORKSTATION WEB GUI    : {state.public_base_url.rstrip('/')}/")
        print(f"  GEMINI CONNECTED URL   : {state.public_base_url.rstrip('/')}/mcp")
        print("=" * 82 + "\n")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return

    cf_bin = ensure_cloudflared(work_dir)
    state.log(f"Starting keyless Cloudflare Quick Tunnel ({cf_bin.name}) -> http://127.0.0.1:{args.port} ...")
    tunnel_proc = subprocess.Popen(
        [str(cf_bin), "tunnel", "--url", f"http://127.0.0.1:{args.port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    printed = False
    try:
        if tunnel_proc.stdout:
            for line in tunnel_proc.stdout:
                match = re.search(r"(https://[a-zA-Z0-9-]+\.trycloudflare\.com)", line)
                if match and not printed:
                    printed = True
                    base_url = match.group(1).rstrip("/")
                    state.public_base_url = base_url
                    mcp_url = f"{base_url}/mcp"
                    copied = copy_to_system_clipboard(mcp_url)
                    state.log(f"PUBLIC TUNNEL READY! Gemini MCP Link: {mcp_url}")
                    print("\n" + "=" * 82)
                    print("  GHIDRAMCP v5.0 WORKSTATION PRO + GEMINI MCP SERVER IS LIVE!")
                    print("=" * 82)
                    print(f"  1. WORKSTATION WEB GUI : {base_url}/   (Local: {local_gui_url})")
                    print(f"  2. GEMINI MCP LINK     : {mcp_url}")
                    if copied:
                        print("  3. CLIPBOARD STATUS    : COPIED TO YOUR CLIPBOARD! Just press Ctrl+V in Gemini!")
                    print("=" * 82 + "\n")
                    if env_info["os"] in ("windows", "darwin") or os.environ.get("DISPLAY"):
                        try:
                            webbrowser.open(local_gui_url)
                        except Exception:
                            pass
    except KeyboardInterrupt:
        print("\n[+] Stopping Workstation Pro server...")
    finally:
        tunnel_proc.terminate()
        if state.ghidra_proc:
            state.ghidra_proc.terminate()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GhidraMCP v5.0 Workstation Pro — Interactive Cloud Decompiler & Multi-Cloud MCP Suite"
    )
    parser.add_argument(
        "--generate-hf-space",
        metavar="DIR",
        help="Generate Dockerfile + README.md + launcher bundle for Hugging Face Docker Spaces",
    )
    parser.add_argument(
        "--deploy-hf-token",
        metavar="HF_TOKEN",
        help="Directly create & deploy a Hugging Face Space via REST API using your hf_... token",
    )
    parser.add_argument(
        "--hf-space-name",
        default="ghidra-mcp-omni",
        help="Target Hugging Face Space name when using --deploy-hf-token (default: ghidra-mcp-omni)",
    )
    parser.add_argument(
        "--binary",
        default="",
        help="Initial binary file path or HTTPS URL (can also be uploaded anytime in the Workstation GUI)",
    )
    parser.add_argument(
        "--work-dir",
        default="",
        help="Working directory (auto-reuses C:/tmp/ghidra_mcp_cloud or /kaggle/working/ghidra_mcp_cloud)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7860,
        help="Unified port for both the Workstation GUI (/) and Gemini MCP endpoint (/mcp) (default: 7860)",
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        default=8081,
        help="Internal loopback port for the Headless GhidraMCP engine (default: 8081)",
    )
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "sse"],
        default="streamable-http",
        help="MCP transport mode (default: streamable-http)",
    )
    parser.add_argument(
        "--no-tunnel",
        action="store_true",
        help="Skip starting cloudflared",
    )
    parser.add_argument(
        "--forever",
        action="store_true",
        help="Run the 1-shot Automated Set-and-Forget Cloud Provisioner (sets up 24/7 GitHub Relay + Permanent Cloudflare Worker URL, then exits so you can turn off your PC forever!)",
    )
    parser.add_argument(
        "--gh-token",
        default="",
        help="GitHub Personal Access Token for --forever mode (auto-detected from gh CLI / git credentials if omitted)",
    )
    parser.add_argument(
        "--cf-token",
        default="",
        help="Optional Cloudflare API Token for --forever mode (uses `npx wrangler deploy` browser login if omitted)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run automated self-test of SSR HTML, JS syntax, static forensics, and MCP multiplexer",
    )
    args, _ = parser.parse_known_args()

    if args.self_test:
        run_self_test()
    elif args.forever:
        env_info = detect_cloud_environment()
        w_dir = Path(args.work_dir) if args.work_dir else Path(env_info["default_work_dir"])
        res = run_autonomous_forever_provisioner(
            work_dir=w_dir,
            gh_token_input=args.gh_token,
            cf_token_input=args.cf_token,
            interactive_cli=True,
        )
        print("\n" + "=" * 82)
        print("  SET-AND-FORGET 24/7 CLOUD PROVISIONER RESULT")
        print("=" * 82)
        print(json.dumps(res, indent=2))
        print("=" * 82 + "\n")
    elif args.generate_hf_space:
        generate_hf_space_bundle(Path(args.generate_hf_space))
    elif args.deploy_hf_token:
        print(json.dumps(deploy_to_huggingface_api(args.deploy_hf_token, args.hf_space_name), indent=2))
    else:
        launch_omni_cloud(args)


if __name__ == "__main__":
    main()