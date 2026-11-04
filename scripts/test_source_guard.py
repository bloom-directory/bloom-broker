"""Regression checks for the frozen, shrink-only executable-source guard."""
import collections
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('source_guard', ROOT / 'test-no-petal-logic.py')
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class SourceGuardTests(unittest.TestCase):
    def test_new_pumpfun_logic_is_detected_case_insensitively(self):
        path = 'crates/bloom-broker/src/new_dispatch.rs'
        self.assertEqual(GUARD.matches(path, 'const PUMPFUN_NEW_CLASS: &str = "pumpfun.new";', []),
                         [path + ':const PUMPFUN_NEW_CLASS: &str = "pumpfun.new";'])

    def test_only_frozen_master_occurrences_can_be_allowed(self):
        baseline = json.loads(GUARD.BASELINE.read_text())
        allowed = json.loads(GUARD.ALLOWLIST.read_text())
        GUARD.validate_allowlist(baseline, allowed)
        rows = [row for row in allowed if 'pumpfun' in row.lower()]
        self.assertTrue(rows)
        self.assertFalse(collections.Counter(rows) - collections.Counter(baseline['master_matches']))
        with self.assertRaises(ValueError):
            GUARD.validate_allowlist(baseline, allowed + ['new.rs:const PUMPFUN_NEW_CLASS = 1;'])

    def test_duplicate_occurrences_cannot_expand_capacity(self):
        baseline = json.loads(GUARD.BASELINE.read_text())
        initial = baseline['initial_allowlist']
        row = next(row for row in initial if 'PUMPFUN_REVIEW_OPERATION_CLASSES:' in row)
        with self.assertRaises(ValueError):
            GUARD.validate_allowlist(baseline, initial + [row])
        GUARD.validate_allowlist(baseline, [entry for entry in initial if entry != row])

    def test_explicit_test_items_are_excluded(self):
        self.assertEqual(GUARD.matches('crates/example/src/lib.rs',
                         '#[cfg(test)] mod tests { const NAME: &str = "pumpfun"; }', []), [])
        self.assertFalse(GUARD.source_path('crates/example/tests/pumpfun.rs'))


if __name__ == '__main__':
    unittest.main()
