"""
sim_engine.py — Automotive manufacturing line simulation (OT layer).

Simulates a simplified body-in-white -> paint -> final-assembly cell as a set
of PLC-controlled stations with realistic sensor telemetry. Pure standard
library; no external dependencies. The engine ticks on a fixed cadence and
exposes a snapshot of the whole plant plus an event log.

The security overlay (asset inventory, Purdue level mapping, trust boundaries,
and a small library of injectable "attacks") lives alongside the physical model
so the same running process can demonstrate BOTH normal operations AND how an
integrity attack on the OT network manifests in the physical process.

NOTE: Everything here is a software simulation. No real fieldbus, no real PLC,
no real device is ever contacted. The "attacks" are state mutations on in-memory
simulated objects, used to show detection — not tools against real equipment.
"""

import math
import random
import time
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Purdue model levels — used by the security overlay to place each asset.
# ─────────────────────────────────────────────────────────────────────────────
PURDUE = {
    0: "Level 0 · Field devices (sensors/actuators)",
    1: "Level 1 · Basic control (PLCs)",
    2: "Level 2 · Area supervisory (SCADA/HMI)",
    3: "Level 3 · Site operations (MES/historian)",
    35: "Level 3.5 · IT/OT DMZ",
    4: "Level 4 · Enterprise IT",
}


@dataclass
class Sensor:
    tag: str            # ISA-style tag, e.g. "WELD-01/CURRENT"
    label: str
    unit: str
    value: float = 0.0
    setpoint: float = 0.0
    lo: float = 0.0         # alarm limits
    hi: float = 0.0
    nominal_noise: float = 0.0
    _phase: float = field(default_factory=lambda: random.uniform(0, math.tau))
    _original_setpoint: float = field(default=0.0, init=False)

    def __post_init__(self):
        self._original_setpoint = self.setpoint

    def status(self) -> str:
        if self.value < self.lo or self.value > self.hi:
            return "alarm"
        # warn band = within 8% of a limit
        span = (self.hi - self.lo) or 1.0
        if self.value < self.lo + 0.08 * span or self.value > self.hi - 0.08 * span:
            return "warn"
        return "ok"


@dataclass
class Station:
    id: str
    name: str
    plc: str            # controlling PLC id
    kind: str           # weld | paint | torque | conveyor | oven
    sensors: list = field(default_factory=list)
    state: str = "running"   # running | idle | fault
    cycle_s: float = 6.0     # nominal takt per unit
    units_done: int = 0
    _t: float = 0.0

    def sensor(self, tag_suffix: str) -> Optional[Sensor]:
        for s in self.sensors:
            if s.tag.endswith(tag_suffix):
                return s
        return None


class PlantSim:
    """The running plant. Thread-safe snapshotting for the web layer.

    mode='automotive'  -> vehicle body-in-white line
    mode='building'    -> smart-building BAS / HVAC / fire-safety line
    """

    def __init__(self, mode="automotive"):
        self._lock = threading.RLock()
        self.mode = mode
        self.tick_count = 0
        self.started_at = time.time()
        self.events = deque(maxlen=200)
        self.active_attacks = {}     # attack_id -> dict(meta)
        self.detections = deque(maxlen=200)
        self.stations = self._build_line()
        self.plcs = self._build_plcs()
        self._log("system", "info", f"{mode.title()} plant cold-started; all stations nominal.")

    # ── construction ────────────────────────────────────────────────────────
    def _build_plcs(self):
        if self.mode == "building":
            return [
                {"id": "BAS-MFC", "name": "Main Facility Controller", "vendor": "Sim-Metasys NAE",
                 "ip": "10.30.1.11", "purdue": 1, "protocol": "BACnet/IP", "firmware": "11.0"},
                {"id": "BAS-CP", "name": "Chiller Plant Controller", "vendor": "Sim-Metasys NAE",
                 "ip": "10.30.1.12", "purdue": 1, "protocol": "BACnet/IP", "firmware": "11.0"},
                {"id": "BAS-FC", "name": "Fire/Smoke Controller", "vendor": "Sim-FireWorks",
                 "ip": "10.30.1.13", "purdue": 1, "protocol": "Modbus TCP", "firmware": "3.2.1"},
                {"id": "BAS-SEC", "name": "Security Access Controller", "vendor": "Sim-CCure",
                 "ip": "10.30.1.14", "purdue": 1, "protocol": "BACnet/IP", "firmware": "2.8"},
            ]
        return [
            {"id": "PLC-BIW", "name": "Body-in-White Cell PLC", "vendor": "Sim-Logix L71",
             "ip": "10.20.1.11", "purdue": 1, "protocol": "EtherNet/IP", "firmware": "32.011"},
            {"id": "PLC-PNT", "name": "Paint Booth PLC", "vendor": "Sim-Logix L71",
             "ip": "10.20.1.12", "purdue": 1, "protocol": "EtherNet/IP", "firmware": "32.011"},
            {"id": "PLC-ASM", "name": "Final Assembly PLC", "vendor": "Sim-S7 1500",
             "ip": "10.20.1.13", "purdue": 1, "protocol": "PROFINET", "firmware": "2.9.2"},
        ]

    def _build_line(self):
        S = []

        if self.mode == "building":
            # Station 1: Air Handling Unit (AHU)
            ahu = Station("AHU-01", "Air Handling Unit", "BAS-MFC", "ahu", cycle_s=6.0)
            ahu.sensors = [
                Sensor("AHU-01/SUPPLYTEMP", "Supply air temp", "°C", setpoint=22.0, lo=18.0, hi=26.0, nominal_noise=0.3),
                Sensor("AHU-01/RETURNTEMP", "Return air temp", "°C", setpoint=24.0, lo=20.0, hi=28.0, nominal_noise=0.4),
                Sensor("AHU-01/FANSPEED", "Fan speed", "%", setpoint=60.0, lo=40.0, hi=80.0, nominal_noise=1.0),
                Sensor("AHU-01/DAMPER", "Damper position", "%", setpoint=50.0, lo=30.0, hi=70.0, nominal_noise=1.5),
            ]
            S.append(ahu)

            # Station 2: Chiller plant
            chiller = Station("CHILLER-01", "Chiller Plant", "BAS-CP", "chiller", cycle_s=7.0)
            chiller.sensors = [
                Sensor("CHILLER-01/CHWSUP", "Chilled water supply", "°C", setpoint=7.0, lo=5.0, hi=9.0, nominal_noise=0.15),
                Sensor("CHILLER-01/CONDP", "Condenser pressure", "bar", setpoint=8.0, lo=6.0, hi=10.0, nominal_noise=0.2),
                Sensor("CHILLER-01/MOTOR", "Compressor load", "%", setpoint=55.0, lo=40.0, hi=75.0, nominal_noise=1.2),
            ]
            S.append(chiller)

            # Station 3: Boiler / hot water loop
            boiler = Station("BOILER-01", "Boiler / Hot Water", "BAS-CP", "boiler", cycle_s=7.0)
            boiler.sensors = [
                Sensor("BOILER-01/HWSUP", "Hot water supply", "°C", setpoint=60.0, lo=50.0, hi=70.0, nominal_noise=0.5),
                Sensor("BOILER-01/GASP", "Gas pressure", "bar", setpoint=1.8, lo=1.4, hi=2.2, nominal_noise=0.05),
                Sensor("BOILER-01/EFF", "Combustion efficiency", "%", setpoint=85.0, lo=75.0, hi=95.0, nominal_noise=1.0),
            ]
            S.append(boiler)

            # Station 4: Fire / smoke control
            fire = Station("FIRE-01", "Fire/Smoke Control", "BAS-FC", "fire", cycle_s=8.0)
            fire.sensors = [
                Sensor("FIRE-01/SMOKE", "Smoke density", "%/m", setpoint=2.0, lo=0.0, hi=5.0, nominal_noise=0.2),
                Sensor("FIRE-01/DAMPER", "Smoke damper position", "%", setpoint=50.0, lo=30.0, hi=70.0, nominal_noise=1.5),
                Sensor("FIRE-01/SUPPRESS", "Suppressant pressure", "bar", setpoint=12.0, lo=10.0, hi=14.0, nominal_noise=0.3),
            ]
            S.append(fire)

            # Station 5: Access control
            access = Station("ACC-01", "Access Control", "BAS-SEC", "access", cycle_s=6.0)
            access.sensors = [
                Sensor("ACC-01/DOOR", "Door secure", "%", setpoint=100.0, lo=95.0, hi=102.5, nominal_noise=0.05),
                Sensor("ACC-01/THROUGH", "People throughput", "p/min", setpoint=15.0, lo=5.0, hi=25.0, nominal_noise=1.5),
                Sensor("ACC-01/LOCKV", "Lock voltage", "V", setpoint=24.0, lo=20.0, hi=28.0, nominal_noise=0.3),
            ]
            S.append(access)

            # Station 6: Elevator bank
            elev = Station("ELEV-01", "Elevator Bank", "BAS-MFC", "elevator", cycle_s=6.0)
            elev.sensors = [
                Sensor("ELEV-01/CABTEMP", "Cab temperature", "°C", setpoint=22.0, lo=18.0, hi=26.0, nominal_noise=0.4),
                Sensor("ELEV-01/MOTOR", "Motor current", "A", setpoint=12.0, lo=8.0, hi=16.0, nominal_noise=0.3),
                Sensor("ELEV-01/SPEED", "Car speed", "m/s", setpoint=1.5, lo=1.0, hi=2.0, nominal_noise=0.05),
            ]
            S.append(elev)

        else:
            # Station 1: Robotic spot welding (BIW)
            weld = Station("WELD-01", "Robotic Spot Weld", "PLC-BIW", "weld", cycle_s=5.5)
            weld.sensors = [
                Sensor("WELD-01/CURRENT", "Weld current", "kA", setpoint=9.8, lo=8.5, hi=11.0, nominal_noise=0.12),
                Sensor("WELD-01/FORCE", "Electrode force", "kN", setpoint=3.4, lo=2.8, hi=4.0, nominal_noise=0.05),
                Sensor("WELD-01/TEMP", "Tip temperature", "°C", setpoint=640, lo=500, hi=760, nominal_noise=6.0),
            ]
            S.append(weld)

            # Station 2: Sealer/adhesive robot (BIW)
            seal = Station("SEAL-02", "Adhesive Dispense", "PLC-BIW", "conveyor", cycle_s=5.5)
            seal.sensors = [
                Sensor("SEAL-02/FLOW", "Bead flow rate", "g/s", setpoint=12.0, lo=9.5, hi=14.5, nominal_noise=0.3),
                Sensor("SEAL-02/PRESS", "Line pressure", "bar", setpoint=5.5, lo=4.5, hi=6.5, nominal_noise=0.08),
            ]
            S.append(seal)

            # Station 3: E-coat / paint booth (PAINT)
            paint = Station("PAINT-03", "Paint Booth", "PLC-PNT", "paint", cycle_s=7.0)
            paint.sensors = [
                Sensor("PAINT-03/BOOTHTEMP", "Booth temperature", "°C", setpoint=23.0, lo=20.0, hi=26.0, nominal_noise=0.4),
                Sensor("PAINT-03/HUMIDITY", "Rel. humidity", "%", setpoint=65.0, lo=55.0, hi=72.0, nominal_noise=1.2),
                Sensor("PAINT-03/FLOW", "Atomizer flow", "cc/min", setpoint=250, lo=210, hi=290, nominal_noise=5.0),
            ]
            S.append(paint)

            # Station 4: Curing oven (PAINT)
            oven = Station("OVEN-04", "Curing Oven", "PLC-PNT", "oven", cycle_s=7.0)
            oven.sensors = [
                Sensor("OVEN-04/ZONE1", "Zone 1 temp", "°C", setpoint=165, lo=150, hi=185, nominal_noise=2.5),
                Sensor("OVEN-04/ZONE2", "Zone 2 temp", "°C", setpoint=175, lo=155, hi=195, nominal_noise=2.5),
            ]
            S.append(oven)

            # Station 5: Torque / fastening (ASSEMBLY)
            torque = Station("TORQ-05", "Powertrain Torque", "PLC-ASM", "torque", cycle_s=6.0)
            torque.sensors = [
                Sensor("TORQ-05/TORQUE", "Fastener torque", "Nm", setpoint=110, lo=95, hi=125, nominal_noise=1.5),
                Sensor("TORQ-05/ANGLE", "Turn angle", "deg", setpoint=90, lo=80, hi=100, nominal_noise=1.0),
            ]
            S.append(torque)

            # Station 6: Conveyor / line speed (spans cell)
            conv = Station("CONV-06", "Main Conveyor", "PLC-ASM", "conveyor", cycle_s=6.0)
            conv.sensors = [
                Sensor("CONV-06/SPEED", "Line speed", "m/min", setpoint=4.5, lo=3.5, hi=5.5, nominal_noise=0.06),
                Sensor("CONV-06/MOTOR", "Motor load", "%", setpoint=62, lo=40, hi=85, nominal_noise=1.5),
            ]
            S.append(conv)

        # seed values at setpoint
        for st in S:
            for s in st.sensors:
                s.value = s.setpoint
        return S

    # ── simulation tick ──────────────────────────────────────────────────────
    def tick(self, dt: float):
        with self._lock:
            self.tick_count += 1
            t = time.time() - self.started_at
            for st in self.stations:
                self._tick_station(st, t, dt)
            self._apply_attacks(t)
            self._run_detection()

    def _tick_station(self, st: Station, t: float, dt: float):
        if st.state == "fault":
            # controller stopped / faulted: freeze sensor values so the primary
            # detection is 'controller offline' rather than cascading limit breaches.
            return

        st._t += dt
        if st._t >= st.cycle_s:
            st._t -= st.cycle_s
            st.units_done += 1

        for s in st.sensors:
            # base = setpoint + gentle sinusoidal process variation + gaussian noise
            drift = 0.015 * (s.hi - s.lo) * math.sin(0.15 * t + s._phase)
            noise = random.gauss(0, s.nominal_noise)
            target = s.setpoint + drift + noise
            # first-order approach so values move smoothly, not jumpily
            s.value += (target - s.value) * min(1.0, 3.0 * dt)

    # ── security overlay: attacks & detection ────────────────────────────────
    def _apply_attacks(self, t: float):
        for aid, atk in list(self.active_attacks.items()):
            kind = atk["kind"]
            if kind == "setpoint_tamper":
                st = self._station(atk["station"])
                s = st.sensor(atk["sensor"]) if st else None
                if s:
                    # attacker rewrites the PLC setpoint itself, so the normal
                    # first-order tick pulls the value toward the malicious target
                    # instead of the safe one — the actual process climbs past the
                    # safe limit within a few seconds of demo time.
                    s.setpoint = atk["target"]
            elif kind == "sensor_spoof":
                st = self._station(atk["station"])
                s = st.sensor(atk["sensor"]) if st else None
                if s:
                    # freeze the reported value at a benign number (replay/spoof)
                    s.value = atk["freeze_at"]
            elif kind == "plc_stop":
                for st in self.stations:
                    if st.plc == atk["plc"]:
                        st.state = "fault"

    def _run_detection(self):
        """Lightweight anomaly + integrity detection the demo can narrate."""
        # primary detection: a PLC stop attack has put stations in fault
        stopped_plcs = {atk["plc"] for atk in self.active_attacks.values() if atk["kind"] == "plc_stop"}
        for plc in stopped_plcs:
            offline = [st.id for st in self.stations if st.plc == plc and st.state == "fault"]
            if offline:
                self._detect(
                    severity="critical",
                    rule="Controller stop / program mode",
                    detail=f"{plc} commanded to stop; offline stations: {', '.join(offline)}",
                    asset=plc,
                )

        for st in self.stations:
            if st.state == "fault":
                continue  # do not pile on secondary sensor alarms for a stopped controller
            for s in st.sensors:
                stt = s.status()
                if stt == "alarm":
                    self._detect(
                        severity="high",
                        rule="Process limit breach",
                        detail=f"{s.tag} = {s.value:.2f}{s.unit} outside safe band "
                               f"[{s.lo:.1f}–{s.hi:.1f}]",
                        asset=st.id,
                    )
        # integrity signal: a frozen/flat sensor with zero variance is suspicious
        for st in self.stations:
            if st.state == "fault":
                continue  # skip flatline on offline stations
            for s in st.sensors:
                if getattr(s, "_history", None) is None:
                    s._history = deque(maxlen=12)
                s._history.append(round(s.value, 4))
                if len(s._history) == s._history.maxlen and len(set(s._history)) == 1:
                    self._detect(
                        severity="critical",
                        rule="Integrity · flatline signature",
                        detail=f"{s.tag} reporting identical value {s.value:.2f} for "
                               f"{s._history.maxlen} cycles — possible sensor spoof/replay.",
                        asset=st.id,
                    )

    def _detect(self, severity, rule, detail, asset):
        # de-dupe: don't spam the same detection every tick
        sig = (rule, detail)
        if self.detections and self.detections[-1].get("_sig") == sig:
            return
        rec = {
            "ts": round(time.time() - self.started_at, 1),
            "severity": severity,
            "rule": rule,
            "detail": detail,
            "asset": asset,
            "_sig": sig,
        }
        self.detections.append(rec)
        self._log("security", severity, f"[{rule}] {detail}")

    # ── operator/attacker controls (exposed via HTTP) ────────────────────────
    def inject_attack(self, kind: str) -> dict:
        with self._lock:
            aid = f"atk-{int(time.time()*1000)%100000}"
            if self.mode == "building":
                if kind == "setpoint_tamper":
                    meta = {
                        "id": aid, "kind": kind, "station": "AHU-01", "sensor": "SUPPLYTEMP",
                        "target": 35.0,   # dangerously high supply air temp
                        "title": "Setpoint tampering — HVAC supply air",
                        "narrative": "Attacker at L2 rewrites the AHU supply-air setpoint over "
                                     "BACnet/IP. The space overheats past the 26°C comfort/safety "
                                     "limit while the BAS reports the unit is running normally.",
                        "purdue_entry": 2,
                        "technique": "Unauthorized BACnet write to AHU setpoint",
                    }
                elif kind == "sensor_spoof":
                    meta = {
                        "id": aid, "kind": kind, "station": "FIRE-01", "sensor": "SMOKE",
                        "freeze_at": 2.0,
                        "title": "Sensor spoofing — smoke density",
                        "narrative": "Attacker replays a 'healthy' 2.0%/m smoke-density reading to "
                                     "the fire panel while a real smoke condition develops. "
                                     "Dampers and suppression may not trigger — a life-safety "
                                     "integrity attack.",
                        "purdue_entry": 1,
                        "technique": "Replay / false data injection to fire panel (Modbus TCP)",
                    }
                elif kind == "plc_stop":
                    meta = {
                        "id": aid, "kind": kind, "plc": "BAS-FC",
                        "title": "Rogue controller stop — fire/smoke",
                        "narrative": "Attacker sends a stop/program-mode command to the Fire/"
                                     "Smoke Controller. Smoke dampers and suppression stop "
                                     "responding. Classic availability attack on an unauthenticated "
                                     "BAS controller.",
                        "purdue_entry": 1,
                        "technique": "Unauthorized controller mode change (Modbus TCP)",
                    }
                else:
                    return {"ok": False, "error": f"unknown attack '{kind}'"}
            else:
                if kind == "setpoint_tamper":
                    meta = {
                        "id": aid, "kind": kind, "station": "OVEN-04", "sensor": "ZONE1",
                        "target": 240.0,   # dangerously high cure temp
                        "title": "Setpoint tampering — curing oven",
                        "narrative": "Attacker at L2 rewrites the Zone-1 temperature setpoint "
                                     "over EtherNet/IP. Actual booth temp climbs past the 185°C "
                                     "safe limit toward 240°C — a scorch/fire and scrap-quality risk.",
                        "purdue_entry": 2,
                        "technique": "Unauthorized command message (no auth on CIP)",
                    }
                elif kind == "sensor_spoof":
                    meta = {
                        "id": aid, "kind": kind, "station": "WELD-01", "sensor": "CURRENT",
                        "freeze_at": 9.8,
                        "title": "Sensor spoofing — weld current",
                        "narrative": "Attacker replays a 'good' 9.8kA weld-current reading to the "
                                     "historian while the real process degrades. Welds fail QA "
                                     "downstream but the line reports healthy — a stealth integrity attack.",
                        "purdue_entry": 1,
                        "technique": "Replay / false data injection to L3 historian",
                    }
                elif kind == "plc_stop":
                    meta = {
                        "id": aid, "kind": kind, "plc": "PLC-ASM",
                        "title": "Rogue PLC stop — final assembly",
                        "narrative": "Attacker sends a stop/program-mode command to the Final "
                                     "Assembly PLC. Torque and conveyor stations fault; the line "
                                     "halts. Classic availability attack on an unauthenticated PLC.",
                        "purdue_entry": 1,
                        "technique": "Unauthorized PLC mode change (PROFINET)",
                    }
                else:
                    return {"ok": False, "error": f"unknown attack '{kind}'"}
            self.active_attacks[aid] = meta
            self._log("security", "warn",
                      f"ATTACK INJECTED · {meta['title']} ({meta['technique']})")
            return {"ok": True, "attack": _clean(meta)}

    def clear_attacks(self) -> dict:
        with self._lock:
            n = len(self.active_attacks)
            self.active_attacks.clear()
            # un-fault everything and re-seed to the original setpoint
            for st in self.stations:
                st.state = "running"
                for s in st.sensors:
                    s.setpoint = s._original_setpoint
                    s.value = s.setpoint
                    if hasattr(s, "_history"):
                        s._history.clear()
            self._log("system", "info", f"All attacks cleared ({n}); line restored to nominal.")
            return {"ok": True, "cleared": n}

    # ── helpers ──────────────────────────────────────────────────────────────
    def _station(self, sid):
        for st in self.stations:
            if st.id == sid:
                return st
        return None

    def _log(self, source, level, msg):
        self.events.appendleft({
            "ts": round(time.time() - self.started_at, 1),
            "source": source, "level": level, "msg": msg,
        })

    # ── snapshots for the web layer ──────────────────────────────────────────
    def snapshot(self) -> dict:
        with self._lock:
            stations = []
            for st in self.stations:
                stations.append({
                    "id": st.id, "name": st.name, "plc": st.plc, "kind": st.kind,
                    "state": st.state, "units_done": st.units_done,
                    "sensors": [{
                        "tag": s.tag, "label": s.label, "unit": s.unit,
                        "value": round(s.value, 2), "setpoint": s.setpoint,
                        "lo": s.lo, "hi": s.hi, "status": s.status(),
                    } for s in st.sensors],
                })
            oee = self._oee()
            return {
                "t": round(time.time() - self.started_at, 1),
                "tick": self.tick_count,
                "stations": stations,
                "plcs": self.plcs,
                "kpis": oee,
                "events": list(self.events)[:40],
                "detections": [_clean(d) for d in list(self.detections)[-30:]][::-1],
                "active_attacks": [_clean(a) for a in self.active_attacks.values()],
            }

    def _oee(self):
        total_units = sum(st.units_done for st in self.stations)
        faulted = sum(1 for st in self.stations if st.state == "fault")
        alarms = sum(1 for st in self.stations for s in st.sensors if s.status() == "alarm")
        n = len(self.stations)
        availability = (n - faulted) / n
        # crude quality proxy: alarms erode quality
        quality = max(0.0, 1.0 - 0.08 * alarms)
        performance = 0.92 if faulted == 0 else 0.55
        oee = availability * quality * performance
        return {
            "throughput_units": total_units,
            "availability": round(availability * 100, 1),
            "quality": round(quality * 100, 1),
            "performance": round(performance * 100, 1),
            "oee": round(oee * 100, 1),
            "active_alarms": alarms,
            "faulted_stations": faulted,
        }


def _clean(d: dict) -> dict:
    """Strip private keys (leading underscore) for JSON output."""
    return {k: v for k, v in d.items() if not k.startswith("_")}


# Security overlay static model (asset inventory + trust boundaries) ──────────
def security_model(plant: PlantSim) -> dict:
    """The threat-model overlay: assets by Purdue level, trust boundaries,
    and the STRIDE-flavored attack surface. Static + a few live counts."""
    is_bldg = plant.mode == "building"
    ctl_label = "Controller" if is_bldg else "PLC"
    assets = []
    for plc in plant.plcs:
        assets.append({
            "id": plc["id"], "name": plc["name"], "type": ctl_label,
            "purdue": plc["purdue"], "ip": plc["ip"], "protocol": plc["protocol"],
            "exposure": "Unauthenticated control protocol; no message signing.",
        })
    # field devices
    for st in plant.stations:
        for s in st.sensors:
            assets.append({
                "id": s.tag, "name": s.label, "type": "Field sensor",
                "purdue": 0, "ip": "—", "protocol": "4-20mA / hardwired",
                "exposure": "No integrity check on process value; spoofable at L1/L2.",
            })
    if is_bldg:
        boundaries = [
            {"from": "Level 4 · Enterprise IT", "to": "Level 3.5 · IT/OT DMZ",
             "control": "Firewall + data diode (egress only)", "risk": "medium",
             "note": "BMS analytics and tenant dashboards cross here; a compromised jump host is the classic pivot."},
            {"from": "Level 3.5 · IT/OT DMZ", "to": "Level 2 · SCADA/HMI",
             "control": "Segmentation VLAN + host firewall", "risk": "high",
             "note": "BMS engineering workstations often dual-homed — primary lateral-movement path."},
            {"from": "Level 2 · SCADA/HMI", "to": "Level 1 · Controllers",
             "control": "NONE (flat control network)", "risk": "critical",
             "note": "BACnet/IP & Modbus TCP carry no authentication; any L2 host can command any controller."},
            {"from": "Level 1 · Controllers", "to": "Level 0 · Field devices",
             "control": "Physical wiring / MS/TP bus", "risk": "low",
             "note": "Requires physical access; out of scope for a network attacker."},
        ]
        attack_surface = [
            {"stride": "Tampering", "target": "Controller setpoints (L1)",
             "scenario": "Rewrite AHU/chiller setpoints over unauthenticated BACnet/IP.",
             "demo": "setpoint_tamper"},
            {"stride": "Spoofing", "target": "Field sensor values (L0→L3)",
             "scenario": "Inject/replay 'healthy' smoke/CO2 readings so the fire panel & BMS show nominal.",
             "demo": "sensor_spoof"},
            {"stride": "Denial of Service", "target": "Controller availability (L1)",
             "scenario": "Force fire/smoke controller to stop/program mode, disabling dampers and suppression.",
             "demo": "plc_stop"},
            {"stride": "Information Disclosure", "target": "BMS historian / energy portal (L3)",
             "scenario": "Exfiltrate tenant occupancy patterns and energy baselines — privacy & IP risk.",
             "demo": None},
            {"stride": "Elevation of Privilege", "target": "Dual-homed BMS workstation (L2/L3.5)",
             "scenario": "Pivot from IT phishing foothold into the flat control LAN.",
             "demo": None},
        ]
    else:
        boundaries = [
            {"from": "Level 4 · Enterprise IT", "to": "Level 3.5 · IT/OT DMZ",
             "control": "Firewall + data diode (egress only)", "risk": "medium",
             "note": "Historian replication crosses here; a compromised jump host is the classic pivot."},
            {"from": "Level 3.5 · IT/OT DMZ", "to": "Level 2 · SCADA/HMI",
             "control": "Segmentation VLAN + host firewall", "risk": "high",
             "note": "HMI engineering workstations often dual-homed — primary lateral-movement path."},
            {"from": "Level 2 · SCADA/HMI", "to": "Level 1 · PLCs",
             "control": "NONE (flat control network)", "risk": "critical",
             "note": "EtherNet/IP & PROFINET carry no authentication; any L2 host can command any PLC."},
            {"from": "Level 1 · PLCs", "to": "Level 0 · Field devices",
             "control": "Physical wiring", "risk": "low",
             "note": "Requires physical access; out of scope for a network attacker."},
        ]
        attack_surface = [
            {"stride": "Tampering", "target": "PLC setpoints (L1)",
             "scenario": "Rewrite oven/weld setpoints over unauthenticated CIP/PROFINET.",
             "demo": "setpoint_tamper"},
            {"stride": "Spoofing", "target": "Field sensor values (L0→L3)",
             "scenario": "Inject/replay 'healthy' readings so the historian & HMI show nominal.",
             "demo": "sensor_spoof"},
            {"stride": "Denial of Service", "target": "PLC availability (L1)",
             "scenario": "Force PLC to stop/program mode, halting the line.",
             "demo": "plc_stop"},
            {"stride": "Information Disclosure", "target": "Historian (L3)",
             "scenario": "Exfiltrate recipe/process parameters — competitor IP theft.",
             "demo": None},
            {"stride": "Elevation of Privilege", "target": "Dual-homed HMI (L2/L3.5)",
             "scenario": "Pivot from IT phishing foothold into the flat control LAN.",
             "demo": None},
        ]
    return {
        "purdue_levels": PURDUE,
        "assets": assets,
        "asset_count": len(assets),
        "trust_boundaries": boundaries,
        "attack_surface": attack_surface,
    }
