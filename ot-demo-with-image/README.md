# Automotive OT Line — Security Demo

A self-contained, local simulation of an automotive manufacturing cell (body-in-white → paint → final assembly) with a live control-room dashboard **and** a security / threat-model overlay. Built to demonstrate to a client both how OT operations look in real time *and* where the control-network attack surface sits — including live, injectable attack scenarios that visibly degrade the simulated line.

**Everything is a software simulation.** No real PLC, fieldbus, sensor, or industrial device is ever contacted. The "attacks" are state mutations on in-memory simulated objects, used purely to demonstrate *detection and impact* on a screen — they are not tools that act against real equipment.

## Requirements

- Python 3.8+ — **standard library only, nothing to `pip install`.**
- A browser.

That's it. No Docker, no Node, no external services.

## Run it

```bash
python3 server.py
```

Then open **http://127.0.0.1:8080** in a browser.

To demo from an EC2 box and view from your laptop, bind all interfaces:

```bash
python3 server.py 0.0.0.0 8080
```

…and open `http://<ec2-public-ip>:8080` (make sure port 8080 is allowed in the security group, or tunnel it over SSH: `ssh -L 8080:localhost:8080 user@ec2-host`).

## Suggested 5-minute demo script

1. **Open on the dashboard, let it run ~15s.** Point out the live mimic diagram — six stations, real telemetry (weld current, oven temp, torque, line speed), OEE holding ~92%. Every value has a live bar with its setpoint marker. This is the "operations" story.

2. **Walk down the Security overlay (Purdue stack).** Note the trust boundary marked **critical** between L2 (SCADA/HMI) and L1 (PLCs): *"NONE — flat control network. EtherNet/IP & PROFINET carry no authentication; any L2 host can command any PLC."* This is the real-world OT reality the client needs to understand.

3. **Click "Tampering — PLC setpoints."** Watch the curing-oven Zone-1 temperature climb past its 185°C safe limit toward 240°C. The station tile goes red and pulses; a **high** detection fires ("Process limit breach"); OEE and Quality drop. Narrate: *an attacker on the supervisory network rewrote a setpoint — a scorch/scrap-quality and safety event.*

4. **Click "Restore line to nominal," then click "Spoofing — field sensor values."** This one is subtler and lands well: the weld-current reading *freezes* at a healthy 9.8 kA. Point at the **critical** detection: *"flatline signature — identical value for 12 cycles — possible sensor spoof/replay."* Narrate: *the line reports healthy while the real process is blind — a stealth integrity attack a naïve dashboard would miss, which is exactly why anomaly/integrity monitoring matters.*

5. **Optionally click "Denial of Service — PLC availability."** Final-assembly PLC goes to fault; torque + conveyor halt; availability drops. The classic OT availability attack.

6. **Restore, and close on the takeaway:** the same visibility that runs the plant is where a security program plugs in — asset inventory, boundary segmentation, and integrity/anomaly detection on the control network.

## What's in the box

| File | Role |
|---|---|
| `sim_engine.py` | The physical + security model. Six PLC-controlled stations with realistic sensor dynamics, an OEE/KPI model, three injectable attack scenarios, and the anomaly/integrity detection logic. Also builds the static threat-model overlay (asset inventory by Purdue level, trust boundaries, STRIDE attack surface). |
| `server.py` | Stdlib HTTP server. Streams the live plant snapshot to the browser over Server-Sent Events (~2 Hz), serves the security model, and exposes the attack/clear control endpoints. |
| `index.html` | The control-room dashboard (single file, no build step). Live mimic diagram, KPI strip, Purdue-model security overlay, attack console, detections feed, event log. |

## The attack scenarios (all simulated)

| Button | STRIDE | What it simulates | What you see |
|---|---|---|---|
| Setpoint tampering | Tampering | Unauthorized setpoint rewrite over unauthenticated CIP/PROFINET (L2→L1) | Oven temp breaches safe limit; high-severity process-limit detection |
| Sensor spoofing | Spoofing | Replay / false-data injection of a "healthy" reading to the historian | Weld current flatlines; critical integrity detection |
| Rogue PLC stop | Denial of Service | Unauthorized PLC stop/program-mode command | Assembly stations fault; line halts; availability drops |

## Extending it for a specific client

- **Different process / sensors:** edit `_build_line()` in `sim_engine.py` — each station is a few lines.
- **More attacks:** add a branch in `inject_attack()` and `_apply_attacks()`, then list it in `security_model()`'s `attack_surface` with a `demo` key so it appears as a button.
- **IT/OT convergence angle:** the `snapshot()` payload is plain JSON — point it at a real Kinesis/Timestream/S3 sink to show OT telemetry flowing into AWS analytics, matching a cloud-side story.
