#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result

fixtures = load('export_fixtures', 'test-recovery-runner.py')
gate = load('publication_gate', 'publication-eligibility.py')

class PublicationTests(unittest.TestCase):
    setUp = fixtures.ExportTests.setUp
    clear = fixtures.ExportTests.clear
    prepare = fixtures.ExportTests.prepare
    runner = fixtures.ExportTests.runner

    def ready(self):
        self.clear(); self.prepare(); runner = self.runner(); runner.run(True)
        entry = self.bundle['manifest']['entries'][0]
        output = Path(entry['output'])
        unit = dict(id='fixture-unit', relative_directory=str(output.parent.relative_to(self.target)),
                    entry_ids=[entry['id']])
        return runner, unit, output

    def test_complete_unit_keeps_path_and_content(self):
        runner, unit, output = self.ready(); before = output.stat()
        result = gate.verify_unit(runner, unit)
        self.assertTrue(result['eligible_at_observation']); self.assertFalse(result['published'])
        self.assertEqual(output.stat(), before)

    def test_missing_record_is_not_a_complete_unit(self):
        runner, unit, output = self.ready(); runner.records.clear()
        with self.assertRaises(ValueError): gate.verify_unit(runner, unit)
        self.assertTrue(output.exists())

    def test_unlisted_file_and_directory_are_rejected(self):
        runner, unit, output = self.ready()
        extra = output.parent / 'extra'; extra.write_bytes(b'not in manifest')
        with self.assertRaises(ValueError): gate.verify_unit(runner, unit)
        extra.unlink(); extra.mkdir()
        with self.assertRaises(ValueError): gate.verify_unit(runner, unit)

    def test_symlink_is_not_published(self):
        runner, unit, output = self.ready()
        (output.parent / 'link').symlink_to(output)
        with self.assertRaises(ValueError): gate.verify_unit(runner, unit)

    def test_replaced_output_is_not_published(self):
        runner, unit, output = self.ready(); output.write_bytes(b'changed')
        with self.assertRaises(Exception): gate.verify_unit(runner, unit)

    def test_incomplete_unit_manifest_is_rejected(self):
        runner, unit, output = self.ready(); unit['entry_ids'] = []
        with self.assertRaises(ValueError): gate.verify_unit(runner, unit)

if __name__ == '__main__': unittest.main(verbosity=2)
