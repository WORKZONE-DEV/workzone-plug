"""Devices: find what's on YOUR network and what each device says it can do.

  python tools/devices.py scan        ask devices on your Wi-Fi/LAN to say what they are
  python tools/devices.py check-profile FILE.json   check a device profile before sharing it

How it works (standard "UPnP/SSDP" discovery, the same thing TVs and speakers use to find each other):
  1. one question is sent to your local network only (multicast 239.255.255.250:1900; it can't
     leave your network)
  2. devices that answer give an address for their description
  3. that description is read ONLY if it's on your own network (a private address), capped in size
     and time, and turned into plain words: "change volume", "play media sent from others"...

Each ability becomes a switch in WORKZONE_HOME/devices.json (Devices tab in the dashboard).
Switches you already set are never overwritten. Enforcing a switch on the device itself needs a
driver for that brand (see devices/README.md); until then the Devices tab says "no driver yet".
Standard library only; read-only towards your devices.
"""
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import xml.parsers.expat
from pathlib import Path
from urllib.parse import urlparse

MAX_DESC = 65536
SSDP = ("239.255.255.250", 1900)
SEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
          "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()

# What a service lets a device do, in plain words.
POWERS = [
    (r"RenderingControl", "change volume and picture"),
    (r"AVTransport", "play media sent from others"),
    (r"ConnectionManager", "accept media connections"),
    (r"ContentDirectory", "share its files and media"),
    (r"dial", "let phones launch apps (casting)"),
    (r"lge-com|webos", "lg remote control (webos)"),
    (r"samsung|MultiScreen", "samsung remote control"),
    (r"WANIPConnection|WANPPPConnection", "open ports on your router"),
    (r"Layer3Forwarding|WANCommonInterfaceConfig", "router settings"),
    (r"ZoneGroupTopology|GroupRendering", "join speaker groups"),
    (r"Printer|PrintBasic", "print"),
    (r"Scanner", "scan documents"),
]
KIND = [(r"MediaRenderer|TV|television|webos|tizen", "tv"), (r"Speaker|ZonePlayer|Sonos", "speaker"),
        (r"InternetGatewayDevice|router", "router"), (r"Printer", "printer"), (r"MediaServer|NAS", "storage")]


def private_http_url(url):
    """Only plain http on this network: a private (home) address, a real port, no tricks."""
    try:
        u = urlparse(url)
        if u.scheme != "http" or not u.hostname or u.username or u.password:
            return False
        ip = ipaddress.ip_address(u.hostname)            # a name isn't accepted: it could point anywhere
        _ = u.port
        return (ip.is_private and not ip.is_loopback and not ip.is_link_local
                and not ip.is_unspecified and not ip.is_multicast)
    except ValueError:
        return False


def power_names(service_types):
    out = []
    for st in service_types:
        for pat, plain in POWERS:
            if re.search(pat, st, re.I):
                if plain not in out:
                    out.append(plain)
                break
        else:
            short = re.sub(r"^urn:[^:]+:service:", "", st).split(":")[0][:30]
            name = "service: " + re.sub(r"[^a-z0-9 ._-]", "", short.lower())
            if short and name not in out:
                out.append(name)
    return out


def parse_description(xml_bytes):
    """Device description XML -> {name, maker, model, kind, services}. Raises ValueError on junk."""
    if len(xml_bytes) > MAX_DESC:
        raise ValueError("description too big")
    # First pass with the raw XML reader: refuse any DTD or entity declaration, in any encoding.
    def refuse(*_):
        raise ValueError("description uses DTD/entities (refused)")
    guard = xml.parsers.expat.ParserCreate()
    guard.StartDoctypeDeclHandler = refuse
    guard.EntityDeclHandler = refuse
    try:
        guard.Parse(xml_bytes, True)
        root = ET.fromstring(xml_bytes)
    except (xml.parsers.expat.ExpatError, ET.ParseError) as e:
        raise ValueError(f"unreadable description ({e})")

    def find(tag):
        for el in root.iter():
            if el.tag.split("}")[-1] == tag and (el.text or "").strip():
                return el.text.strip()
        return ""
    services = [el.text.strip() for el in root.iter() if el.tag.split("}")[-1] == "serviceType" and el.text]
    dtype = find("deviceType")
    text = " ".join([dtype, find("modelName"), find("manufacturer"), find("friendlyName")])
    kind = next((k for pat, k in KIND if re.search(pat, text, re.I)), "device")
    clean = lambda s: re.sub("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]", "", s)[:60]
    return {"name": clean(find("friendlyName") or find("modelName") or "Unknown device"),
            "maker": clean(find("manufacturer")), "model": clean(find("modelName")),
            "kind": kind, "services": services[:40]}


def fetch_description(url, timeout=3):
    if not private_http_url(url):
        raise ValueError("not an address on your own network")
    opener = urllib.request.build_opener(_NoRedirects)
    deadline = time.monotonic() + timeout
    out = b""
    with opener.open(url, timeout=timeout) as r:
        while len(out) <= MAX_DESC:
            if time.monotonic() > deadline:
                raise ValueError("description too slow")
            chunk = r.read(4096)
            if not chunk:
                break
            out += chunk
    return out


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        raise urllib.error.URLError("redirects are not followed")


def discover(timeout=3.0):
    """Ask the local network; returns a list of {address, name, maker, model, kind, powers}."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)      # TTL 1: never past your router
    s.settimeout(timeout)
    locations = {}
    deadline, packets = time.monotonic() + timeout + 1, 0
    try:
        s.sendto(SEARCH, SSDP)
        while len(locations) < 64 and packets < 512 and time.monotonic() < deadline:
            packets += 1
            s.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            m = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
            if m:
                loc = m.group(1).decode("ascii", "replace")
                if private_http_url(loc) and urlparse(loc).hostname == addr[0]:   # it must describe itself
                    locations.setdefault(loc, addr[0])
    finally:
        s.close()
    found = {}
    stop = time.monotonic() + 20                      # the whole scan never takes more than ~25 seconds
    for loc, ip in locations.items():
        if time.monotonic() > stop:
            break
        try:
            d = parse_description(fetch_description(loc))
        except Exception:  # noqa: BLE001 - one odd device never stops the scan
            continue
        cur = found.setdefault(ip, {"address": ip, "name": d["name"], "maker": d["maker"], "model": d["model"],
                                    "kind": d["kind"], "powers": []})
        for p in power_names(d["services"]):
            if p not in cur["powers"]:
                cur["powers"].append(p)
        if cur["kind"] == "device":
            cur["kind"] = d["kind"]
    return list(found.values())


def merge(devices_json_path, found):
    """Add what was found to devices.json. Switches you already set are left exactly as they are."""
    p = Path(devices_json_path)
    try:
        cur = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"devices": []}
        if not isinstance(cur, dict) or not isinstance(cur.get("devices"), list):
            cur = {"devices": []}
    except (OSError, ValueError):
        raise ValueError("devices.json isn't readable; fix or move it first (it was left untouched)")
    by_addr = {d.get("address"): d for d in cur["devices"] if isinstance(d, dict) and d.get("address")}
    added = 0
    for f in found:
        d = by_addr.get(f["address"])
        if d is None:
            d = {"name": f["name"], "kind": f["kind"], "driver": "", "address": f["address"],
                 "maker": f["maker"], "model": f["model"], "powers": {}}
            cur["devices"].append(d)
            by_addr[f["address"]] = d
            added += 1
        if not isinstance(d.get("powers"), dict):
            d["powers"] = {}
        for pw in f["powers"]:
            d["powers"].setdefault(pw, True)                 # it CAN do this today; switch it off if you like
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cur, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return added


PROFILES = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "devices" / "profiles"
PROFILE_KINDS = {"tv", "speaker", "phone", "router", "printer", "storage", "device"}
POWER_NAME = re.compile(r"^[a-z0-9][a-z0-9 ._():-]{0,60}$")


def check_profile(data):
    """A device profile -> list of plain problems (empty = good). See devices/README.md."""
    p = []
    if not isinstance(data, dict):
        return ["a profile is a JSON object"]
    if data.get("profile") != "0":
        p.append('"profile" must be "0"')
    for k in ("brand", "model"):
        if not isinstance(data.get(k), str) or not data[k].strip() or len(data[k]) > 60:
            p.append(f'"{k}" must be text, up to 60 characters')
    if data.get("kind") not in PROFILE_KINDS:
        p.append('"kind" must be one of ' + ", ".join(sorted(PROFILE_KINDS)))
    m = data.get("match")
    if not isinstance(m, dict) or not any(isinstance(m.get(k), str) and m[k].strip() for k in ("manufacturer", "model_contains")):
        p.append('"match" needs a manufacturer and/or model_contains, so a scan can recognise the device')
    elif any(k in m and not isinstance(m[k], str) for k in ("manufacturer", "model_contains")):
        p.append('"match" values must be text')
    powers = data.get("powers")
    if not isinstance(powers, dict) or not powers:
        p.append('"powers" must list at least one power')
    else:
        for name, v in powers.items():
            if not POWER_NAME.match(str(name)):
                p.append(f'power name {name!r}: short lowercase words only')
            if not isinstance(v, dict) or not isinstance(v.get("can_switch_off_from_work_zone"), bool):
                p.append(f'power {name!r}: needs can_switch_off_from_work_zone (true or false)')
            elif not isinstance(v.get("how"), str) or len(v["how"]) < 8:
                p.append(f'power {name!r}: needs "how" (plain steps to switch it off on the device)')
    text = json.dumps(data, ensure_ascii=False)
    if re.search(r"[\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]", text):
        p.append("contains hidden characters")
    if re.search(r"\b(serial|imei|mac address)\b\s*[:=]", text, re.I):
        p.append("looks like it contains personal device data (serial / IMEI / MAC): leave it out")
    return p


def load_profiles(folder=PROFILES):
    out = []
    for f in sorted(Path(folder).glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not check_profile(d):
            out.append(d)
    return out


def profile_for(device, profiles):
    """The first profile whose match fits this device's maker/model/name, or None."""
    maker, model = str(device.get("maker", "")).lower(), (str(device.get("model", "")) + " " + str(device.get("name", ""))).lower()
    for pr in profiles:
        m = pr["match"]
        if m.get("manufacturer") and m["manufacturer"].lower() not in maker:
            continue
        if m.get("model_contains") and m["model_contains"].lower() not in model:
            continue
        return pr
    return None


def main(argv):
    if argv[:1] == ["check-profile"] and len(argv) == 2:
        try:
            problems = check_profile(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        except (OSError, ValueError) as e:
            problems = [f"unreadable: {e}"]
        for x in problems:
            print("  NO   " + x)
        print("Profile looks good. Share it!" if not problems else f"{len(problems)} thing(s) to fix.")
        return 0 if not problems else 1
    if argv[:1] != ["scan"]:
        print(__doc__)
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import workzone
    found = discover()
    added = merge(workzone.devices_file(), found)
    for f in found:
        print(f"  {f['name'][:28]:28}  {f['kind']:8}  {f['address']:15}  {', '.join(f['powers'])[:80]}")
    print(f"Found {len(found)} device(s), {added} new. Switches are in {workzone.devices_file()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
