import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402


class Normalize(unittest.TestCase):
    def test_accepts_and_cleans(self):
        self.assertEqual(build.normalize("Ads.Example.COM."), "ads.example.com")
        self.assertEqual(build.normalize("bücher.example"), "xn--bcher-kva.example")
        self.assertEqual(build.normalize("a_b.example.com"), "a_b.example.com")

    def test_rejects_non_domains(self):
        for bad in ["", "localhost", "localhost.localdomain", "1.2.3.4", "single", "a..b.com", "-a.com",
                    "a-.com", "a b.com", "x" * 64 + ".com", ("a." * 130) + "com", "bad!.com"]:
            self.assertIsNone(build.normalize(bad), bad)


class Parse(unittest.TestCase):
    def test_hosts_handles_crlf_comments_and_ips(self):
        text = "# c\r\n0.0.0.0 a.example.com\r\n127.0.0.1 b.example.com # why\r\n0.0.0.0 0.0.0.0\r\n255.255.255.255 broadcasthost\r\n\r\n"
        names, rejected = build.parse(text, "hosts")
        self.assertEqual(names, {"a.example.com", "b.example.com"})
        self.assertEqual(rejected, 2)

    def test_domains(self):
        names, _ = build.parse("# h\nA.Example.com\nb.example.com # x\n10.0.0.1\n", "domains")
        self.assertEqual(names, {"a.example.com", "b.example.com"})

    def test_adblock_takes_only_plain_domain_rules(self):
        text = "[Adblock Plus]\n! c\n||a.example.com^\n||b.example.com^$important\n@@||c.example.com^\n||d.example.com/path^\n||e.example.com^$third-party\n##.ad\n"
        names, _ = build.parse(text, "adblock")
        self.assertEqual(names, {"a.example.com", "b.example.com"})


class Collapse(unittest.TestCase):
    def test_subdomains_of_listed_parents_are_dropped(self):
        names = {"a.com", "x.a.com", "y.x.a.com", "b.com", "x.b.com"}
        self.assertEqual(build.collapse(names), {"a.com", "b.com"})

    def test_keeps_unrelated_and_sibling_names(self):
        names = {"x.a.com", "y.a.com"}
        self.assertEqual(build.collapse(names), names)

    def test_covered(self):
        blocked = {"a.com"}
        self.assertTrue(build.covered("a.com", blocked))
        self.assertTrue(build.covered("x.y.a.com", blocked))
        self.assertFalse(build.covered("ba.com", blocked))


class Tier(unittest.TestCase):
    def loaded(self):
        return {
            "s1": ({"ads.example.com", "x.ads.example.com", "keep.test"}, {"tiers": ["lite", "full"]}),
            "s2": ({"mal.test"}, {"tiers": ["full"]}),
        }

    def test_tiers_select_sources(self):
        lite = build.build_tier("lite", self.loaded(), set(), set())["final"]
        full = build.build_tier("full", self.loaded(), set(), set())["final"]
        self.assertEqual(lite, {"ads.example.com", "keep.test"})
        self.assertEqual(full, {"ads.example.com", "keep.test", "mal.test"})

    def test_allow_removes_name_and_its_subdomains(self):
        t = build.build_tier("full", self.loaded(), set(), {"ads.example.com"})
        self.assertEqual(t["final"], {"keep.test", "mal.test"})
        self.assertEqual(t["allow_stuck"], [])

    def test_allow_below_a_blocked_parent_is_reported(self):
        t = build.build_tier("full", self.loaded(), set(), {"sub.keep.test"})
        self.assertIn("keep.test", t["final"])
        self.assertEqual(t["allow_stuck"], ["sub.keep.test"])

    def test_extra_block_is_added(self):
        t = build.build_tier("lite", self.loaded(), {"mine.test"}, set())
        self.assertIn("mine.test", t["final"])


class Cosmetic(unittest.TestCase):
    def test_accepts_the_rule_shapes_in_use(self):
        for rule in ["||shoplive.cloud^", "accounts.google.com/gsi/*", "ebay.com###dp-live-events-carousel",
                     'ebay.com##[class*="dp-live-"]', 'ebay.com##li.a:has(a[href*="/ebaylive"])',
                     "##.ad", "a.com,~b.a.com##.x", "ebay.com#@#.ok", "@@||ebay.com^$document"]:
            self.assertIsNone(build.check_rule(rule), rule)

    def test_rejects_what_it_cannot_vouch_for(self):
        for rule in ['ebay.com##div[class*="a"', "ebay.com##div{display:none}", "ebay.com##+js(aopr, x)",
                     "ebay.com#?#div:has-text(x)", "two words", " ebay.com##.x", "ebay.com##.x ", "ebay.com##a)("]:
            self.assertIsNotNone(build.check_rule(rule), rule)

    def test_build_dedupes_and_reports_bad_lines(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "cosmetic.txt").write_text("! c\n||a.test^\n||a.test^\n\nb.test##.x\n")
            (d / "out").mkdir()
            self.assertEqual(build.build_cosmetic(d / "cosmetic.txt", d / "out", "T"), 2)
            out = (d / "out" / "cosmetic.txt").read_text().splitlines()
            self.assertEqual(out[-2:], ["||a.test^", "b.test##.x"])
            (d / "bad.txt").write_text("ok.test##.x\nb.test##{\n")
            with self.assertRaises(SystemExit) as e:
                build.build_cosmetic(d / "bad.txt", d / "out", "T")
            self.assertIn("bad.txt:2", str(e.exception))


class LoadSources(unittest.TestCase):
    def load(self, text):
        src = [{"name": "x", "url": "u", "format": "plain", "tiers": ["full"]}]
        orig, build.fetch = build.fetch, lambda url, cache: text
        try:
            return build.load_sources(src, None)
        finally:
            build.fetch = orig

    def test_empty_source_fails(self):
        with self.assertRaises(SystemExit):
            self.load("# only a comment\n")

    def test_small_source_passes(self):
        self.assertEqual(self.load("0.0.0.0 a.example\n")["x"][0], {"a.example"})


if __name__ == "__main__":
    unittest.main()
