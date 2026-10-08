"""Offline only: temporary files, fake downloads and fake health responses."""
import base64
import copy
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deploy import protocol as p
from deploy.puller import Puller,REF_URL,fetch_fixed,API,blob_sha

SOURCE='a'*40
RELEASE='b'*40

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state';self.state.mkdir()
        self.site=Path(self.temp.name)/'nw6';self.site.mkdir()
        self.backups=Path(self.temp.name)/'backups';self.backups.mkdir()
        self.old_page=b'original approved test page'
        (self.site/'index.html').write_bytes(self.old_page)
        (self.site/'index.html').chmod(0o644)
        self.manifest,self.archive=p.build(SOURCE)
        self.calls=[]
    def fetch(self,url,limit):
        self.calls.append(url)
        if url==REF_URL:return json.dumps({'object':{'sha':RELEASE,'type':'commit'}}).encode()
        files={'release.json':json.dumps(self.manifest).encode(),'site.tar.gz':self.archive}
        if url==API+'/git/commits/'+RELEASE:return json.dumps({'sha':RELEASE,'tree':{'sha':'d'*40}}).encode()
        if url==API+'/git/trees/'+'d'*40:return json.dumps({'sha':'d'*40,'truncated':False,'tree':[{'path':n,'mode':'100644','type':'blob','sha':blob_sha(v),'size':len(v)} for n,v in files.items()]}).encode()
        for name,data in files.items():
            if url==API+'/contents/'+name+'?ref='+RELEASE:return json.dumps({'name':name,'path':name,'type':'file','encoding':'base64','size':len(data),'sha':blob_sha(data),'content':base64.b64encode(data).decode()}).encode()
        raise AssertionError('unexpected URL')
    def healthy(self,expected):
        return p.digest((self.site/'index.html').read_bytes())==expected
    def run_puller(self,fetch=None,check=None):
        return Puller(self.site,self.state,self.backups,fetch or self.fetch,check or self.healthy).run()
    def assert_unchanged(self):
        self.assertEqual((self.site/'index.html').read_bytes(),self.old_page)
    def malicious_tar(self,name='index.html',kind=tarfile.REGTYPE,payload=None,duplicate=False,extra=False):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            item=tarfile.TarInfo(name);item.type=kind
            data=p.render(SOURCE) if payload is None else payload
            if kind in (tarfile.REGTYPE,tarfile.AREGTYPE):
                item.size=len(data);archive.addfile(item,io.BytesIO(data))
            else:item.linkname='../outside';archive.addfile(item)
            if duplicate:archive.addfile(item,io.BytesIO(data))
            if extra:
                other=tarfile.TarInfo('run.sh');other.size=3;archive.addfile(other,io.BytesIO(b'bad'))
        self.archive=gzip.compress(raw.getvalue())
        self.manifest['archive_bytes']=len(self.archive);self.manifest['archive_sha256']=p.digest(self.archive)
    def test_deterministic_build(self):
        a,b=p.build(SOURCE);self.assertEqual(a,self.manifest);self.assertEqual(b,self.archive)
        self.assertEqual(p.unpack(a,b),p.render(SOURCE))
    def test_activate_and_unchanged(self):
        result=self.run_puller();self.assertEqual(result['status'],'activated')
        self.assertEqual((self.site/'index.html').read_bytes(),p.render(SOURCE))
        self.assertFalse((self.state/'pending.json').exists())
        self.assertEqual(self.run_puller()['status'],'unchanged')
    def test_downloads_pinned_to_same_commit(self):
        self.run_puller()
        self.assertEqual(len(self.calls),5)
        self.assertEqual(self.calls[1],API+'/git/commits/'+RELEASE)
        self.assertTrue(all('?ref='+RELEASE in u for u in self.calls[3:]))
        self.assertFalse(any('/nw6-release/' in u for u in self.calls[1:]))
    def test_download_failure_keeps_current(self):
        for failure_at in range(5):
            self.calls=[]
            def fail(url,limit):
                if len(self.calls)==failure_at:raise TimeoutError('simulated download timeout')
                return self.fetch(url,limit)
            with self.assertRaises(TimeoutError):self.run_puller(fetch=fail)
            self.assert_unchanged()
    def test_bad_integrity_keeps_current(self):
        self.archive=self.archive[:-1]+bytes([self.archive[-1]^1])
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_bad_gzip_keeps_current(self):
        self.archive=b'not gzip';self.manifest['archive_bytes']=len(self.archive);self.manifest['archive_sha256']=p.digest(self.archive)
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_path_traversal_absolute_backslash(self):
        for name in ['../escape','/absolute','a/../../escape','a\\index.html','index.html/../escape']:
            self.malicious_tar(name=name)
            with self.subTest(name=name),self.assertRaises(p.ReleaseError):self.run_puller()
            self.assert_unchanged()
    def test_symlink_and_hardlink_tar(self):
        for kind in [tarfile.SYMTYPE,tarfile.LNKTYPE]:
            self.malicious_tar(kind=kind)
            with self.assertRaises(p.ReleaseError):self.run_puller()
            self.assert_unchanged()
    def test_duplicate_or_extra_member(self):
        for flag in ['duplicate','extra']:
            self.malicious_tar(**{flag:True})
            with self.assertRaises(p.ReleaseError):self.run_puller()
            self.assert_unchanged()
    def test_oversized_member(self):
        self.malicious_tar(payload=b'x'*(p.MAX_HTML+1))
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_archive_download_limit(self):
        self.manifest['archive_bytes']=p.MAX_ARCHIVE+1
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_expansion_bomb(self):
        self.archive=gzip.compress(b'\0'*(p.MAX_EXPANDED_TAR+1))
        self.manifest['archive_bytes']=len(self.archive);self.manifest['archive_sha256']=p.digest(self.archive)
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_html_hash_mismatch_rejected(self):
        self.malicious_tar(payload=b'<script>malicious()</script>')
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_bad_manifest_and_urls(self):
        for key,value in [('archive_bytes',True),('source_sha','main'),('files',{'../escape':{}}),('url','https://example.com/')]:
            candidate=copy.deepcopy(self.manifest);candidate[key]=value
            with self.subTest(key=key),self.assertRaises(p.ReleaseError):p.validate_manifest(candidate)
    def test_duplicate_json_keys(self):
        with self.assertRaises(p.ReleaseError):p.parse_json(b'{"schema":1,"schema":2}')
    def test_json_limit(self):
        with self.assertRaises(p.ReleaseError):p.parse_json(b' '*(p.MAX_JSON+1))
    def test_invalid_ref_no_artifact_fetch(self):
        def fetch(url,limit):return json.dumps({'object':{'sha':'main','type':'commit'}}).encode()
        with self.assertRaises(p.ReleaseError):self.run_puller(fetch=fetch)
        self.assert_unchanged()
    def test_target_page_symlink_outside(self):
        page=self.site/'index.html';page.unlink()
        outside=Path(self.temp.name)/'outside';outside.write_bytes(self.old_page)
        os.symlink(str(outside),str(page))
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assertEqual(self.calls,[])
    def test_initial_page_symlink(self):
        page=self.site/'index.html';page.unlink()
        outside=Path(self.temp.name)/'outside';outside.write_bytes(self.old_page)
        os.symlink(str(outside),str(page))
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assertEqual(self.calls,[])
    def test_backup_symlink(self):
        candidate=self.backups/('old-'+p.digest(self.old_page)+'.html')
        outside=Path(self.temp.name)/'outside';outside.write_bytes(self.old_page)
        os.symlink(str(outside),str(candidate))
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_state_directory_symlink(self):
        alias=Path(self.temp.name)/'alias';os.symlink(str(self.state),str(alias))
        with self.assertRaises(p.ReleaseError):Puller(self.site,alias,self.backups,self.fetch,self.healthy).run()
        self.assertEqual(self.calls,[])
    def test_lock_symlink_does_not_write_outside(self):
        outside=Path(self.temp.name)/'outside';outside.write_bytes(b'unchanged')
        os.symlink(str(outside),str(self.state/'pull.lock'))
        with self.assertRaises(OSError):self.run_puller()
        self.assertEqual(outside.read_bytes(),b'unchanged');self.assert_unchanged()
    def test_health_failure_rolls_back(self):
        checks=[]
        def check(expected):
            checks.append(expected);return expected==p.digest(self.old_page)
        with self.assertRaises(p.ReleaseError):self.run_puller(check=check)
        self.assert_unchanged();self.assertEqual(len(checks),3)
        self.assertFalse((self.state/'pending.json').exists())
    def test_health_exception_rolls_back(self):
        def check(expected):
            if expected==p.digest(self.old_page):return True
            raise RuntimeError('simulated nginx failure')
        with self.assertRaises(p.ReleaseError):self.run_puller(check=check)
        self.assert_unchanged()
    def test_interrupted_health_recovers_next_run(self):
        def interrupt(expected):
            if expected==p.digest(self.old_page):return True
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.run_puller(check=interrupt)
        self.assertTrue((self.state/'pending.json').exists())
        self.calls=[];result=self.run_puller()
        self.assertEqual(result['status'],'recovered_previous')
        self.assert_unchanged();self.assertEqual(self.calls,[])
    def test_bad_recovery_journal_refuses(self):
        (self.state/'pending.json').write_text(json.dumps({'backup':'../escape','new_digest':'c'*64,'old_digest':p.digest(self.old_page)}))
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_retention_capacity_safe_failure(self):
        for i in range(20):(self.backups/('unused-'+str(i))).mkdir()
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
    def test_fixed_urls_reject_before_network(self):
        with mock.patch('urllib.request.build_opener',side_effect=AssertionError('no network')):
            for url in ['https://example.com/a','http://api.github.com/anything','https://raw.githubusercontent.com/'+p.REPO+'/nw6-release/release.json','https://raw.githubusercontent.com/'+p.REPO+'/'+RELEASE+'/run.sh']:
                with self.subTest(url=url),self.assertRaises(p.ReleaseError):fetch_fixed(url,8192)
    def test_nonexistent_installation_safe_failure(self):
        with self.assertRaises(p.ReleaseError):Puller(self.site,Path(self.temp.name)/'missing',self.backups,self.fetch,self.healthy).run()
        self.assertEqual(self.calls,[])
    def test_no_server_command_execution(self):
        import ast
        tree=ast.parse((ROOT/'deploy/puller.py').read_text())
        forbidden={'subprocess','eval','exec','system','popen','extractall','extract'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):self.assertTrue(all(x.name!='subprocess' for x in node.names))
            if isinstance(node,ast.Call):
                name=node.func.attr if isinstance(node.func,ast.Attribute) else (node.func.id if isinstance(node.func,ast.Name) else '')
                self.assertNotIn(name,forbidden)
    def test_publisher_missing_token_fails_before_git(self):
        from deploy import publish
        artifact=Path(self.temp.name)/'artifact';artifact.mkdir()
        (artifact/'release.json').write_text(json.dumps(self.manifest));(artifact/'site.tar.gz').write_bytes(self.archive)
        argv=['publish','--directory',str(artifact),'--expected-digest',self.manifest['archive_sha256']]
        isolated={'GITHUB_REPOSITORY':p.REPO,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_SHA':SOURCE}
        class FakeOS:environ=isolated
        with mock.patch.object(publish,'os',FakeOS),mock.patch.object(sys,'argv',argv),mock.patch.object(publish,'git',side_effect=AssertionError('no git')):
            with self.assertRaises(SystemExit):publish.main()
    def test_permission_failure_preserves_page(self):
        with mock.patch.object(Puller,'atomic_page',side_effect=PermissionError('offline denial')):
            with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_unchanged()
        self.assertFalse((self.state/'pending.json').exists())
    def test_concurrent_editor_change_not_overwritten(self):
        foreign=b'concurrent administrator edit'
        def check(expected):
            (self.site/'index.html').write_bytes(foreign)
            return True
        with self.assertRaises(p.ReleaseError):self.run_puller(check=check)
        self.assertEqual((self.site/'index.html').read_bytes(),foreign)
        self.assertTrue((self.state/'pending.json').exists())
    def test_busy_lock_no_download(self):
        import fcntl
        fd=os.open(str(self.state/'pull.lock'),os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(self.run_puller(),{'status':'busy'})
            self.assertEqual(self.calls,[])
        finally:os.close(fd)
    def test_atomic_replace_is_single_file_not_symlink(self):
        import deploy.puller as module
        original=module.os.replace;replaced=[]
        def observe(source,destination):
            if str(destination)==str(self.site/'index.html'):
                self.assertFalse(Path(source).is_symlink());replaced.append(str(destination))
            return original(source,destination)
        with mock.patch.object(module.os,'replace',side_effect=observe):self.run_puller()
        self.assertEqual(replaced,[str(self.site/'index.html')])
        self.assertEqual(set(x.name for x in self.site.iterdir()),{'index.html'})
    def test_publisher_uses_fixed_branch_without_force(self):
        from deploy import publish
        import subprocess,contextlib
        artifact=Path(self.temp.name)/'publish';artifact.mkdir()
        (artifact/'release.json').write_text(json.dumps(self.manifest));(artifact/'site.tar.gz').write_bytes(self.archive)
        argv=['publish','--directory',str(artifact),'--expected-digest',self.manifest['archive_sha256']]
        isolated={'GITHUB_REPOSITORY':p.REPO,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_SHA':SOURCE,'GH_TOKEN':'offline-placeholder-not-a-credential'}
        class FakeOS:environ=isolated
        calls=[]
        def fake_git(args,cwd,env,allowed=(0,)):
            calls.append(args)
            return subprocess.CompletedProcess(args,2 if args[0]=='ls-remote' else 0,b'',b'')
        with mock.patch.object(publish,'os',FakeOS),mock.patch.object(sys,'argv',argv),mock.patch.object(publish,'git',side_effect=fake_git),contextlib.redirect_stdout(io.StringIO()):publish.main()
        self.assertIn(['push','origin','HEAD:refs/heads/nw6-release'],calls)
        self.assertFalse(any('--force' in arg or '--force-with-lease' in arg for command in calls for arg in command))
    def assert_consistent(self,expected):
        self.assertEqual((self.site/'index.html').read_bytes(),expected)
        active=json.loads((self.state/'active.json').read_text())
        self.assertEqual(active['page_sha256'],p.digest(expected))
        self.assertFalse((self.state/'pending.json').exists())
    def test_v1_v2_text_changes_without_server_program_change(self):
        installed=(ROOT/'deploy/puller.py').read_bytes(),(ROOT/'deploy/protocol.py').read_bytes()
        v1=b'<html><body>Version ONE</body></html>'
        v2=b'<html><body>Version TWO changed text</body></html>'
        self.manifest,self.archive=p.build(SOURCE,v1);self.run_puller();self.assert_consistent(v1)
        self.manifest,self.archive=p.build('c'*40,v2)
        with mock.patch.dict(globals(),{'RELEASE':'e'*40}):self.run_puller()
        self.assert_consistent(v2)
        self.assertEqual(installed,((ROOT/'deploy/puller.py').read_bytes(),(ROOT/'deploy/protocol.py').read_bytes()))
    def test_build_reads_fixed_repository_entry(self):
        entry=ROOT/'index.html';original=entry.read_bytes()
        try:
            entry.write_bytes(b'<html>actual new repository entry</html>')
            manifest,archive=p.build(SOURCE)
            self.assertEqual(p.unpack(manifest,archive),entry.read_bytes())
        finally:entry.write_bytes(original)
    def test_active_write_failure_rolls_back_consistently(self):
        q=Puller(self.site,self.state,self.backups,self.fetch,self.healthy);original=q.write_json;armed=[True]
        def fail(path,value):
            if path.name=='active.json' and armed[0]:armed[0]=False;raise OSError('active write failure')
            return original(path,value)
        with mock.patch.object(q,'write_json',fail),self.assertRaises(p.ReleaseError):q.run()
        self.assert_consistent(self.old_page)
    def test_crash_after_active_recovers_page_and_active(self):
        q=Puller(self.site,self.state,self.backups,self.fetch,self.healthy);original=q.write_json
        def crash(path,value):
            original(path,value)
            if path.name=='active.json':raise KeyboardInterrupt()
        with mock.patch.object(q,'write_json',crash),self.assertRaises(KeyboardInterrupt):q.run()
        self.assertEqual(q.run()['status'],'recovered_previous');self.assert_consistent(self.old_page)
    def test_journal_unlink_failure_rolls_back_consistently(self):
        original=Path.unlink;armed=[True]
        def fail(path,*args,**kwargs):
            if path==self.state/'pending.json' and armed[0]:armed[0]=False;raise OSError('unlink failed')
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,'unlink',fail),self.assertRaises(p.ReleaseError):self.run_puller()
        self.assert_consistent(self.old_page)
    def test_final_fsync_failure_no_journal_no_false_rollback(self):
        q=Puller(self.site,self.state,self.backups,self.fetch,self.healthy);original=q.sync_dir;armed=[True]
        def fail(directory):
            if directory==self.state and (self.state/'active.json').exists() and not (self.state/'pending.json').exists() and armed[0]:
                armed[0]=False;raise OSError('final fsync failure')
            return original(directory)
        with mock.patch.object(q,'sync_dir',fail),self.assertRaisesRegex(p.ReleaseError,'durability unconfirmed'):q.run()
        self.assert_consistent(p.render(SOURCE));self.assertEqual(q.run()['status'],'unchanged')
    def test_recovery_preserves_other_editor(self):
        def crash(expected):
            if expected!=p.digest(self.old_page):raise KeyboardInterrupt()
            return True
        with self.assertRaises(KeyboardInterrupt):self.run_puller(check=crash)
        foreign=b'<html>administrator edit</html>'
        (self.site/'index.html').write_bytes(foreign)
        with self.assertRaises(p.ReleaseError):self.run_puller()
        self.assertEqual((self.site/'index.html').read_bytes(),foreign)
        self.assertTrue((self.state/'pending.json').exists())
    def test_backup_hash_drift_stops_recovery(self):
        def crash(expected):
            if expected!=p.digest(self.old_page):raise KeyboardInterrupt()
            return True
        with self.assertRaises(KeyboardInterrupt):self.run_puller(check=crash)
        before=(self.site/'index.html').read_bytes()
        next(self.backups.iterdir()).write_bytes(b'tampered')
        with self.assertRaisesRegex(p.ReleaseError,'backup drift'):self.run_puller()
        self.assertEqual((self.site/'index.html').read_bytes(),before)
        self.assertTrue((self.state/'pending.json').exists())
    def test_single_file_limit_consistency(self):
        page=b'x'*p.MAX_HTML;manifest,archive=p.build(SOURCE,page)
        self.assertEqual(p.unpack(manifest,archive),page)
        (self.site/'index.html').write_bytes(page)
        q=Puller(self.site,self.state,self.backups,self.fetch,self.healthy)
        self.assertEqual(q.read_page(),page);q.save_backup(page)
        with self.assertRaises(p.ReleaseError):p.build(SOURCE,page+b'x')
        (self.site/'index.html').write_bytes(page+b'x')
        with self.assertRaises(p.ReleaseError):q.read_page()
    def test_workflow_manual_immutable_fixed_context(self):
        text=(ROOT/'.github/workflows/publish-nw6-static.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('inputs:',text)
        for trigger in ('push:', 'pull_request:', 'schedule:', 'workflow_call:'):self.assertNotIn(trigger,text)
        self.assertNotIn('REQUESTED_SHA',text)
        self.assertIn('ref: ${{ github.sha }}',text)
        self.assertIn('environment: nw6-static-release',text)
        self.assertIn("github.repository == 'dziiiii/cloud-web-demo'",text)
        self.assertIn("github.ref == 'refs/heads/main'",text)
if __name__=='__main__':unittest.main(verbosity=2)
