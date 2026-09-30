# Devices: see what a device may do, switch any of it off

Smart TVs, speakers and gadgets on Wi-Fi or Bluetooth can do a lot you never see: listen, show things
on screen, talk to the internet. The idea is the same as for plugs: **every power is a switch you control.**

## What works now (preview)

The dashboard has a **Devices** tab. It lists your devices from `WORKZONE_HOME/devices.json` and shows each
power as a tick box. Changing a switch is saved straight back to that file.

```json
{
  "devices": [
    {
      "name": "Living room TV",
      "kind": "tv",
      "driver": "",
      "powers": {
        "microphone": false,
        "show pop-ups": false,
        "internet": true,
        "cast from phones": true
      }
    }
  ]
}
```

Power names are short, lowercase words. Anything else in the file is ignored.

## What comes next: drivers

A switch only protects you when something enforces it. That is a **driver**: a small adapter for one
brand's way of talking to its devices. A driver will:

1. read the switches for its device from `devices.json`
2. apply them to the device (turn the microphone off, block pop-ups, and so on) where the device allows it
3. report back honestly what it could and could not enforce, in plain words

Drivers follow the same rules as everything else here: they run on your computer only, they hold no user
data, they never widen a power, and every change is logged. Until a driver is installed for a device, the
Devices tab says "no driver yet", so it never pretends to protect something it doesn't.

## Scan my network

Press **scan my network** in the Devices tab (or run `python tools/devices.py scan`).
Work Zone asks the devices on your own Wi-Fi/LAN to say what they are, the same standard way TVs and
speakers find each other (UPnP/SSDP). It only reads descriptions from private addresses on your network,
refuses anything odd, and never sends anything outside it. Each thing a device says it can do becomes a
switch; switches you already set are never changed.

## Device profiles: help map every device

Every new phone, TV, speaker or gadget works a little differently. A **device profile** records, for one
model, what it can do and how each power can be switched off. Anyone can write one for a device they own
and share it; the project can also target devices to test.

### The format

One JSON file per model (see [profiles/example-tv.json](profiles/example-tv.json)):

| Field | What |
|---|---|
| `profile` | Format version, `"0"` |
| `brand`, `model`, `kind` | What the device is (`kind`: tv, speaker, phone, router, printer, storage, device) |
| `match` | How the Devices tab recognises it from a network scan: `manufacturer` and `model_contains` |
| `powers` | Each power by name, with `can_switch_off_from_work_zone` (true only when a driver really does it) and `how` (plain steps to switch it off on the device itself) |
| `tested_by`, `tested_on` | Who tested it and when |
| `notes` | Anything else: software version, what didn't work |

### Rules

- **Honest only.** `can_switch_off_from_work_zone` is `true` only when a tested driver really does it. Otherwise
  the profile tells people how to do it themselves, and the Devices tab shows those steps.
- **No personal data.** No serial numbers, no account names, no addresses.
- **Check it first:** `python tools/devices.py check-profile devices/profiles/your-device.json`.
- Share it as a pull request.
