import contextlib, io, json, os, sys, tempfile, unittest
from datetime import date
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import policy_checker as pc

TODAY = date(2026, 10, 28)
P = dict(pc.DEFAULT_POLICY)


def check(pw, user="testuser", changed="2026-10-01", policy=P):
    return pc.check_password(user, pw, changed, policy, TODAY)


class TestRules(unittest.TestCase):
    def test_strong_password_passes(self):
        self.assertTrue(check("Blue-Giraffe-Lamp-47!").compliant)

    def test_too_short(self):
        self.assertTrue(any("Too short" in v for v in check("Ab1!xyZ").violations))

    def test_boundary_length_exactly_min_is_ok(self):
        r = check("Gk7!Mq2#Vz9@")           # exactly 12 chars
        self.assertFalse(any("Too short" in v for v in r.violations))

    def test_missing_classes(self):
        v = check("alllowercaseonly").violations
        for msg in ("uppercase", "digit", "symbol"):
            self.assertTrue(any(msg in x for x in v), msg)

    def test_contains_username_case_insensitive(self):
        r = check("MyALICE-Pass#99x", user="alice")
        self.assertIn("Contains the username", r.violations)

    def test_common_password(self):
        self.assertIn("Is a commonly used password", check("password123").violations)

    def test_sequence_detected(self):
        self.assertTrue(pc.has_sequence("xx1234yy"))
        self.assertTrue(pc.has_sequence("zzDCBAzz"))      # descending, case-insens.
        self.assertFalse(pc.has_sequence("x7q2m9"))

    def test_repeat_run(self):
        self.assertEqual(pc.max_repeat_run("aabbbbc"), 4)
        self.assertEqual(pc.max_repeat_run(""), 0)
        self.assertTrue(any("Repeats" in v for v in check("Zaaaa-Lamp-47!Q").violations))

    def test_age_limit(self):
        r = check("Blue-Giraffe-Lamp-47!", changed="2024-01-01")
        self.assertTrue(any("days old" in v for v in r.violations))

    def test_age_disabled(self):
        pol = dict(P, max_age_days=0)
        self.assertTrue(check("Blue-Giraffe-Lamp-47!", changed="2020-01-01", policy=pol).compliant)

    def test_invalid_date_flagged(self):
        r = check("Blue-Giraffe-Lamp-47!", changed="garbage")
        self.assertTrue(any("Invalid last_changed" in v for v in r.violations))

    def test_empty_password_does_not_crash(self):
        r = check("")
        self.assertFalse(r.compliant)


class TestPolicyAndIO(unittest.TestCase):
    def test_unknown_policy_key_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"min_lenght": 8}, f)   # typo on purpose
        with self.assertRaises(ValueError):
            pc.load_policy(f.name)
        os.unlink(f.name)

    def test_report_never_contains_plaintext_password(self):
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        res = pc.audit_file(os.path.join(d, "synthetic_accounts.csv"), P, TODAY)
        blob = json.dumps([r.__dict__ for r in res])
        self.assertNotIn("password123", blob)
        self.assertNotIn("Tr0ub4dor", blob)

    def test_sample_file_expected_outcomes(self):
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        res = {r.username: r for r in pc.audit_file(os.path.join(d, "synthetic_accounts.csv"), P, TODAY)}
        for ok in ("alice", "erin", "judy"):
            self.assertTrue(res[ok].compliant, ok)
        for bad in ("bob", "carol", "dave", "frank", "grace", "heidi", "ivan", "mallory"):
            self.assertFalse(res[bad].compliant, bad)

    def test_cli_exit_codes(self):
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pc.main([os.path.join(d, "synthetic_accounts.csv"), "--today", "2026-10-28"]), 1)
            self.assertEqual(pc.main(["does_not_exist.csv"]), 2)


class TestRegressions(unittest.TestCase):
    """Cases for bugs found in code review."""

    def _tmp(self, name, text, encoding="utf-8"):
        d = tempfile.mkdtemp()
        path = os.path.join(d, name)
        with open(path, "w", encoding=encoding, newline="") as f:
            f.write(text)
        return path

    def _quiet_main(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return pc.main(argv)

    # --- date handling -------------------------------------------------
    def test_invalid_today_is_an_error(self):
        csv_path = self._tmp("a.csv", "username,password,last_changed\n"
                                      "zed,Blue-Giraffe-Lamp-47!,2026-10-01\n")
        self.assertEqual(self._quiet_main([csv_path, "--today", "garbage"]), 2)

    def test_blank_and_missing_date_flagged(self):
        for blank in ("", "   ", None):
            r = check("Blue-Giraffe-Lamp-47!", user="zed", changed=blank)
            self.assertIn("Missing last_changed date", r.violations, repr(blank))

    def test_future_date_flagged(self):
        r = check("Blue-Giraffe-Lamp-47!", user="zed", changed="2030-01-01")
        self.assertTrue(any("in the future" in v for v in r.violations))
        self.assertIsNone(r.password_age_days)

    def test_today_boundary_is_not_future(self):
        r = check("Blue-Giraffe-Lamp-47!", user="zed", changed="2026-10-28")
        self.assertTrue(r.compliant)

    # --- malformed input -----------------------------------------------
    def test_wrong_policy_type_rejected(self):
        for bad in ({"min_length": "12"}, {"min_length": -1},
                    {"min_length": True}, {"require_upper": "yes"}):
            path = self._tmp("p.json", json.dumps(bad))
            with self.assertRaises(ValueError, msg=str(bad)):
                pc.load_policy(path)

    def test_non_object_policy_rejected(self):
        with self.assertRaises(ValueError):
            pc.load_policy(self._tmp("p.json", "[1, 2]"))

    def test_bad_policy_via_cli_exits_2(self):
        csv_path = self._tmp("a.csv", "username,password,last_changed\n")
        pol = self._tmp("p.json", '{"min_length": "12"}')
        self.assertEqual(self._quiet_main([csv_path, "--policy", pol]), 2)

    def test_short_csv_row_exits_2_not_crash(self):
        csv_path = self._tmp("a.csv", "username,password,last_changed\nbob\n")
        self.assertEqual(self._quiet_main([csv_path]), 2)

    def test_row_missing_only_date_is_flagged_not_crash(self):
        csv_path = self._tmp("a.csv", "username,password,last_changed\n"
                                      "zed,Blue-Giraffe-Lamp-47!\n")
        res = pc.audit_file(csv_path, P, TODAY)
        self.assertIn("Missing last_changed date", res[0].violations)

    def test_utf8_bom_csv_accepted(self):
        csv_path = self._tmp("a.csv", "username,password,last_changed\n"
                                      "zed,Blue-Giraffe-Lamp-47!,2026-10-01\n",
                             encoding="utf-8-sig")
        res = pc.audit_file(csv_path, P, TODAY)
        self.assertEqual(res[0].username, "zed")
        self.assertTrue(res[0].compliant)

    # --- rule behaviour ------------------------------------------------
    def test_repeat_run_zero_disables_rule(self):
        pol = dict(P, max_repeat_run=0)
        r = check("Zaaaa-Lamp-47!Q", user="zed", policy=pol)
        self.assertFalse(any("Repeats" in v for v in r.violations))

    def test_common_password_variants_caught(self):
        for pw in ("Password123!", "PASSWORD", "P@ssw0rd!!", "Welcome1!!",
                   "L3tm31n"):
            self.assertTrue(pc.is_common_password(pw), pw)
        self.assertFalse(pc.is_common_password("Blue-Giraffe-Lamp-47!"))
        self.assertFalse(pc.is_common_password("Tr0ub4dor&Cloud!92"))

    def test_short_username_not_substring_checked(self):
        r = check("Blue-Giraffe-Lamp-47!", user="a")
        self.assertNotIn("Contains the username", r.violations)
        r = check("Blue-Giraffe-Lamp-47!", user="blue")
        self.assertIn("Contains the username", r.violations)

    def test_username_min_len_configurable(self):
        pol = dict(P, username_min_len=1)
        self.assertIn("Contains the username",
                      check("Blue-Giraffe-Lamp-47!", user="a", policy=pol).violations)

    def test_unicode_digit_not_counted_as_digit(self):
        v = check("Abcdefghijklmn\u00b2!", user="zed").violations
        self.assertIn("Missing digit", v)

    def test_space_counts_as_symbol(self):
        v = check("correct horse 9 Staple", user="zed").violations
        self.assertNotIn("Missing symbol", v)

    # --- output safety -------------------------------------------------
    def test_csv_report_neutralises_formula_injection(self):
        res = [pc.Result("=cmd|calc", False, ["x"], 5, 1)]
        path = os.path.join(tempfile.mkdtemp(), "r.csv")
        pc.write_csv(res, path)
        with open(path, encoding="utf-8") as f:
            self.assertIn("\'=cmd|calc", f.read().replace("\r", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
