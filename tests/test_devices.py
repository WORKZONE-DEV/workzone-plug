"""Devices: discovery only looks at your own network, turns services into plain switches,
and never overwrites a switch you set."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import devices  # noqa: E402

TV = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
 <friendlyName>Living room TV</friendlyName><manufacturer>LG Electronics</manufacturer><modelName>OLED55</modelName>
 <serviceList>
  <service><serviceType>urn:schemas-upnp-org:service:RenderingControl:1</serviceType></service>
  <service><serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType></service>
  <service><serviceType>urn:dial-multiscreen-org:service:dial:1</serviceType></service>
  <service><serviceType>urn:example-com:service:Mystery:1</serviceType></service>
 </serviceList></device></root>"""


class Devices(unittest.TestCase):
    def test_description_becomes_plain_switches(self):
        d = devices.parse_description(TV)
        self.assertEqual((d["name"], d["kind"], d["maker"]), ("Living room TV", "tv", "LG Electronics"))
        self.assertEqual(devices.power_names(d["services"]),
                         ["change volume and picture", "play media sent from others",
                          "let phones launch apps (casting)", "service: mystery"])

    def test_only_your_own_network(self):
        ok = ["http://192.168.1.20:1400/desc.xml", "http://10.0.0.5/d.xml", "http://172.16.3.4:8080/x"]
        bad = ["https://192.168.1.20/x", "http://8.8.8.8/x", "http://127.0.0.1:8770/api", "http://tv.local/x",
               "http://user:pw@192.168.1.2/x", "http://169.254.1.1/x", "file:///etc/passwd", "http://192.168.1.2:99999/x"]
        for u in ok:
            self.assertTrue(devices.private_http_url(u), u)
        for u in bad:
            self.assertFalse(devices.private_http_url(u), u)
        with self.assertRaises(ValueError):
            devices.fetch_description("http://8.8.8.8/x")

    def test_hostile_descriptions_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><root>&a;</root>'
        for junk in [bomb, b"<root>", b"x" * (devices.MAX_DESC + 1)]:
            with self.assertRaises(ValueError):
                devices.parse_description(junk)
        utf16 = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY a "AAAA">]><root><device>'
                 '<friendlyName>&a;</friendlyName></device></root>').encode("utf-16")
        with self.assertRaises(ValueError):
            devices.parse_description(utf16)
        self.assertFalse(devices.private_http_url("http://0.0.0.0/x"))
        sneaky = TV.replace(b"Living room TV", "Living\u202eroom".encode())
        self.assertNotIn("\u202e", devices.parse_description(sneaky)["name"], "hidden characters stripped")

    def test_merge_adds_new_and_keeps_your_switches(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "devices.json"
            found = [{"address": "192.168.1.20", "name": "TV", "maker": "LG", "model": "X", "kind": "tv",
                      "powers": ["change volume and picture", "play media sent from others"]}]
            self.assertEqual(devices.merge(f, found), 1)
            data = json.loads(f.read_text())
            data["devices"][0]["powers"]["play media sent from others"] = False      # you switched it off
            f.write_text(json.dumps(data))
            found[0]["powers"].append("let phones launch apps (casting)")
            self.assertEqual(devices.merge(f, found), 0, "same device, not added twice")
            p = json.loads(f.read_text())["devices"][0]["powers"]
            self.assertFalse(p["play media sent from others"], "your switch is left exactly as it was")
            self.assertTrue(p["let phones launch apps (casting)"])

    def test_merge_never_clobbers_a_broken_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "devices.json"
            f.write_text("{not json")
            with self.assertRaises(ValueError):
                devices.merge(f, [])
            self.assertEqual(f.read_text(), "{not json")



class Labels(unittest.TestCase):
    def test_same_power_twice_is_one_switch(self):
        st = ["urn:schemas-upnp-org:service:Layer3Forwarding:1", "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"]
        self.assertEqual(devices.power_names(st), ["router settings"])


class Profiles(unittest.TestCase):
    def test_example_profile_is_valid_and_matches(self):
        pr = json.loads((ROOT / "devices" / "profiles" / "example-tv.json").read_text(encoding="utf-8"))
        self.assertEqual(devices.check_profile(pr), [])
        self.assertIs(devices.profile_for({"maker": "Example Electronics", "model": "ExampleTV 55"}, [pr]), pr)
        self.assertIsNone(devices.profile_for({"maker": "Other", "model": "ExampleTV"}, [pr]))

    def test_bad_profiles_are_explained(self):
        self.assertTrue(devices.check_profile([]))
        bad = {"profile": "0", "brand": "X", "model": "Y", "kind": "toaster", "match": {}, "powers": {"Mic!": {}}}
        problems = " ".join(devices.check_profile(bad))
        for word in ("kind", "match", "Mic!"):
            self.assertIn(word, problems)
        leak = dict(json.loads((ROOT / "devices" / "profiles" / "example-tv.json").read_text(encoding="utf-8")), notes="serial: 123")
        self.assertTrue(any("personal" in x for x in devices.check_profile(leak)))
        odd = dict(json.loads((ROOT / "devices" / "profiles" / "example-tv.json").read_text(encoding="utf-8")),
                   match={"manufacturer": 5, "model_contains": "X"})
        self.assertTrue(devices.check_profile(odd), "a number where text belongs is refused, so matching can't crash")

if __name__ == "__main__":
    unittest.main()
