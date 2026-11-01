#!/usr/bin/env python3
"""Local temporary metadata fixtures only. No NAS or actual export writes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('october',Path(__file__).with_name('october-export-manifest.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class OctoberManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.base=self.root/'volume2';self.base.mkdir()
        self.mount=self.root/'usb';self.mount.mkdir();self.target=self.mount/'Recovery_October2026'
        self.month=self.base/'ExampleShare'/'店A'/'2026'/'10月';self.month.mkdir(parents=True)
        self.proposal=dict(jobs=[dict(store='店A',source=str(self.month),output_relative=str(self.month.relative_to(self.base)))],
            destination=dict(proposed_mount=str(self.mount),proposed_root=self.target.name,filesystem='NTFS',expected_usb='fixture-only',last_free_bytes=100_000_000_000,last_observed_at=1234,reserve_bytes=50_000_000_000,metadata_budget_bytes=10_000_000_000))

    def make(self,proposal=None):return m.make_manifest(proposal or self.proposal,self.base,self.target,now=5678)

    def codes(self,bundle):return {x['code'] for x in bundle['exceptions']}

    def test_clear_cipher_exclusions_exact_layout_hashes_and_no_output_creation(self):
        (self.month/'plain.jpg').write_bytes(b'plain')
        (self.month/'cipher.psd.L0CK3D').write_bytes(b'x'*(588+100))
        (self.month/'read-me3.txt').write_text('ransom note')
        (self.month/'READ-ME3.TXT.L0CK3D').write_bytes(b'x'*600)
        (self.month/'#recycle').mkdir();(self.month/'#recycle'/'old.L0CK3D').write_bytes(b'x'*700)
        (self.month/'@eaDir').mkdir();(self.month/'.hidden').write_bytes(b'x')
        (self.month/'link.jpg').symlink_to(self.month/'plain.jpg')
        result=self.make();entries=result['manifest']['entries']
        self.assertEqual({e['operation'] for e in entries},{'copy','decrypt'})
        self.assertEqual(result['summary']['expected_output_bytes'],105)
        cipher=next(e for e in entries if e['operation']=='decrypt')
        self.assertEqual(cipher['output_relative'],'ExampleShare/店A/2026/10月/cipher.psd')
        self.assertEqual(cipher['source_identity']['size'],688);self.assertFalse(cipher['footer_validated'])
        self.assertEqual(result['summary']['observed_capacity']['observed_at'],1234)
        self.assertTrue(result['summary']['preflight_passed']);self.assertFalse(result['manifest']['executable'])
        self.assertFalse(self.target.exists())
        self.assertIn('excluded-known-ransom-note',self.codes(result));self.assertIn('excluded-symlink',self.codes(result))
        for name in ['manifest','exceptions','summary']:
            self.assertEqual(result['hashes'][name],hashlib.sha256(m.encode(result[name])).hexdigest())

    def test_decoded_clear_collision_and_casefolded_collision_block(self):
        (self.month/'same.jpg.L0CK3D').write_bytes(b'x'*600);(self.month/'same.jpg').write_bytes(b'x')
        (self.month/'PHOTO.jpg.L0CK3D').write_bytes(b'x'*600);(self.month/'photo.jpg').write_bytes(b'x')
        result=self.make();self.assertIn('planned-file-name-collision',self.codes(result))
        self.assertFalse(result['summary']['preflight_passed']);self.assertFalse(result['manifest']['executable'])
        self.assertEqual(len(result['manifest']['entries']),4);self.assertFalse(self.target.exists())

    def test_planned_file_directory_conflict_detected(self):
        (self.month/'folder').mkdir();(self.month/'folder'/'child.jpg').write_bytes(b'x')
        (self.month/'folder.L0CK3D').write_bytes(b'x'*600)
        self.assertIn('planned-file-directory-collision',self.codes(self.make()))

    def test_portable_name_validation_and_tail_normalization(self):
        for name in ['CON.jpg','LPT1','COM¹.txt','bad:name.jpg','bad?name','tail.','tail ']:
            with self.subTest(name=name):self.assertTrue(m.component_issues(name))
        self.assertIn('ntfs-component-over-255-utf16-units',m.component_issues('😀'*128))
        self.assertIn('windows-unencodable-name',m.component_issues('\udcff'))
        self.assertEqual(m.portable_key(['Photo.JPG. ']),m.portable_key(['photo.jpg']))
        self.assertFalse(m.component_issues('正常照片.jpg'))
        (self.month/'CON.jpg').write_bytes(b'x');(self.month/'tail.').write_bytes(b'x')
        result=self.make();self.assertFalse(result['summary']['preflight_passed'])
        self.assertIn('windows-reserved-device-name',self.codes(result));self.assertIn('windows-trailing-dot-or-space',self.codes(result))

    def test_existing_target_casefold_file_and_parent_conflicts(self):
        (self.month/'photo.jpg').write_bytes(b'x')
        parent=self.target/self.month.relative_to(self.base);parent.mkdir(parents=True)
        (parent/'PHOTO.JPG').write_bytes(b'keep existing')
        result=self.make();self.assertIn('existing-target-collision',self.codes(result))
        self.assertEqual((parent/'PHOTO.JPG').read_bytes(),b'keep existing')
        (parent/'PHOTO.JPG').unlink();(parent/'block').write_bytes(b'keep parent file')
        (self.month/'block').mkdir();(self.month/'block'/'child.jpg').write_bytes(b'x')
        self.assertIn('existing-target-parent-not-directory',self.codes(self.make()))

    def test_long_windows_path_is_warning_not_absolute_storage_rejection(self):
        parent=self.month
        for name in ['a'*80,'b'*80,'c'*80]:parent=parent/name;parent.mkdir()
        (parent/'photo.jpg').write_bytes(b'x')
        result=self.make();self.assertIn('legacy-windows-long-path-warning',self.codes(result))
        self.assertTrue(result['summary']['preflight_passed']);self.assertFalse(result['manifest']['executable'])

    def test_exact_capacity_budgets_and_short_cipher_block(self):
        (self.month/'photo.jpg').write_bytes(b'x'*100)
        proposal=copy.deepcopy(self.proposal);proposal['destination']['last_free_bytes']=60_000_000_099
        result=self.make(proposal);self.assertIn('capacity-budget-exceeded',self.codes(result))
        self.assertEqual(result['summary']['observed_capacity']['budget_bytes'],99)
        # Smaller proposal budgets cannot reduce the mandatory 50GB + 10GB reserves.
        proposal['destination']['reserve_bytes']=0;proposal['destination']['metadata_budget_bytes']=0
        self.assertIn('capacity-budget-exceeded',self.codes(self.make(proposal)))
        (self.month/'broken.L0CK3D').write_bytes(b'short')
        result=self.make();self.assertIn('ciphertext-shorter-than-footer',self.codes(result))
        self.assertFalse(result['summary']['preflight_passed'])

    def test_scope_escape_wrong_month_duplicate_and_symlink_root(self):
        for change in ['month','output','duplicate','outside']:
            p=copy.deepcopy(self.proposal)
            if change=='month':p['jobs'][0]['source']=str(self.month.parent/'11月')
            if change=='output':p['jobs'][0]['output_relative']='wrong'
            if change=='duplicate':p['jobs'].append(copy.deepcopy(p['jobs'][0]))
            if change=='outside':p['jobs'][0]['source']=str(self.root/'other')
            with self.subTest(change=change),self.assertRaises(m.Refused):self.make(p)
        held=self.month.with_name('held');self.month.rename(held);self.month.symlink_to(held,target_is_directory=True)
        result=self.make();self.assertIn('source-directory-unreadable',self.codes(result));self.assertFalse(result['summary']['preflight_passed'])

    def test_local_metadata_artifacts_only_and_no_overwrite(self):
        (self.month/'photo.jpg').write_bytes(b'x');result=self.make()
        artifacts=self.root/'artifacts';artifacts.mkdir();m.write_bundle(result,artifacts)
        self.assertEqual({p.name for p in artifacts.iterdir()},{'manifest.json','exceptions.json','summary.json','hashes.json'})
        with self.assertRaises(FileExistsError):m.write_bundle(result,artifacts)
        with self.assertRaises(m.Refused):m.write_bundle(result,self.mount)
        with self.assertRaises(m.Refused):m.write_bundle(result,self.base)
        self.assertFalse(self.target.exists())

if __name__=='__main__':unittest.main(verbosity=2)
