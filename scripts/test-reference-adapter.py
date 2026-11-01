#!/usr/bin/env python3
"""Check generic scope, marker and bundle boundaries using temporary fixtures."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


fixtures = load('adapter_fixtures', 'test-october-export-runner.py')
adapter = load('reference_adapter', 'recover.py')


class AdapterTests(unittest.TestCase):
    setUp = fixtures.ExportTests.setUp
    clear = fixtures.ExportTests.clear
    cipher = fixtures.ExportTests.cipher

    def plan_args(self, output):
        identity = self.root / 'target.json'; identity.write_text(json.dumps(self.identity))
        return ['recover.py', 'plan', '--source-base', str(self.base), '--approved-source-root', str(self.month),
                '--target-root', str(self.target), '--target-identity', str(identity), '--bundle-out', str(output)]

    def test_single_root_plan_and_runner_scope(self):
        self.month = self.base / 'CustomerBranch' / 'UrgentProject'; self.month.mkdir(parents=True)
        self.clear(); self.cipher()
        output = self.root / 'bundle.json'
        with patch.object(sys, 'argv', self.plan_args(output)):
            # Host free space may be below the mandatory 60 GB reserve.
            self.assertIn(adapter.main(), (0, 2))
        bundle = json.loads(output.read_text())
        self.assertEqual(len(bundle['manifest']['entries']), 2)
        self.assertFalse(self.target.exists()); self.assertFalse(self.state.exists())
        with patch.object(sys, 'argv', self.plan_args(output)):
            with self.assertRaises(FileExistsError): adapter.main()

    def test_bundle_may_not_be_written_to_source_or_target(self):
        self.clear()
        for output in [self.month / 'bundle.json', self.mount / 'bundle.json']:
            with patch.object(sys, 'argv', self.plan_args(output)):
                with self.assertRaises(ValueError): adapter.main()
            self.assertFalse(output.exists())

    def test_missing_or_malformed_marker_is_rejected_before_loading_key(self):
        args = ['run', '--bundle', 'missing.json', '--target-identity', 'missing.json', '--state-dir', '/unused',
                '--approved-source-root', '/unused/source', '--expected-manifest-sha256', '0' * 64]
        for extra in [[], ['--marker', 'a1'], ['--marker', 'zzzzzzzz']]:
            result = subprocess.run([sys.executable, '-B', str(HERE / 'recover.py'), *args, *extra], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_no_implicit_constructor_marker(self):
        self.clear(); bundle = fixtures.m.pre.make_manifest(self.proposal, self.base, self.target)
        with self.assertRaises(fixtures.m.r.Refused):
            fixtures.m.Export(bundle, self.identity, self.state, bundle['hashes']['manifest'], fixtures.MASTER,
                              identity_probe=lambda mount: self.identity)
        self.assertFalse(self.target.exists()); self.assertFalse(self.state.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
