"""SIMULATED API envelopes with target-observed field names, never target JSON.
The target only observed index.html metadata; releases below are synthetic fixtures.
"""
import base64,copy,email.message,io,json,time,unittest,urllib.error
from pathlib import Path
from unittest import mock
import test_static_release as old
from deploy import protocol as p
from deploy import puller as q
class Contents(unittest.TestCase):
 def setUp(self):
  self.f=old.Tests();self.f.setUp();self.addCleanup(self.f.doCleanups)
 def change(self,kind,transform):
  def fetch(url,limit):
   data=self.f.fetch(q.API+'/git/trees/'+'d'*40 if '/git/trees/' in url else url,limit)
   if kind in url:return json.dumps(transform(json.loads(data))).encode()
   return data
  return fetch
 def reject(self,kind,transform):
  with self.assertRaises(p.ReleaseError):self.f.run_puller(fetch=self.change(kind,transform))
  self.f.assert_unchanged()
 def test_normal_simulated_field_shapes_and_wrapped_base64(self):
  def wrap(v):
   v['content']='\n'.join(v['content'][n:n+60] for n in range(0,len(v['content']),60))+'\n'
   v['download_url']='https://untrusted.invalid/never-fetch';v['url']='https://untrusted.invalid/never-fetch';return v
  self.assertEqual(self.f.run_puller(fetch=self.change('/contents/',wrap))['status'],'activated')
  self.assertTrue(all(url.startswith(q.API) for url in self.f.calls))
 def test_symlink_executable_submodule_or_tree_rejected(self):
  for change in ({'mode':'120000'},{'mode':'100755'},{'mode':'160000','type':'commit'},{'mode':'040000','type':'tree'}):
   def mutate(v):v['tree'][0].update(change);return v
   self.reject('/git/trees/',mutate)
 def test_root_tree_truncated_extra_missing_duplicate_path_sha(self):
  for mutation in ('truncated','extra','missing','duplicate','path','sha','type','size'):
   def mutate(v):
    if mutation=='truncated':v['truncated']=True
    if mutation=='extra':v['tree'].append(dict(v['tree'][0],path='extra.html'))
    if mutation=='missing':v['tree'].pop()
    if mutation=='duplicate':v['tree'][1]=v['tree'][0]
    if mutation=='path':v['tree'][0]['path']='../release.json'
    if mutation=='sha':v['tree'][0]['sha']='main'
    if mutation=='type':v['tree'][0]['type']='symlink'
    if mutation=='size':v['tree'][0]['size']=True
    return v
   with self.subTest(mutation=mutation):self.reject('/git/trees/',mutate)
 def test_commit_tree_mixed_commit_or_wrong_tree_refused(self):
  for change in ({'sha':'c'*40},{'tree':{'sha':'main'}},{'tree':{'sha':'e'*40}}):
   self.reject('/git/commits/',lambda v:dict(v,**change))
  self.reject('/git/trees/',lambda v:dict(v,sha='e'*40))
 def test_contents_name_path_type_encoding_size_blob_sha(self):
  for change in ({'name':'other'},{'path':'../release.json'},{'type':'symlink'},{'encoding':'none'},{'size':True},{'size':1},{'sha':old.RELEASE},{'sha':'f'*40}):
   self.reject('/contents/release.json',lambda v:dict(v,**change))
 def test_strict_ascii_base64_unknown_whitespace_and_bad_padding(self):
  for content in ('é','\t',' ','\r\n','!','eA===','eB=='):
   self.reject('/contents/release.json',lambda v:dict(v,content=content))
 def test_decoded_size_and_git_blob_sha_both_verified(self):
  self.reject('/contents/release.json',lambda v:dict(v,content=base64.b64encode(b'x'*v['size']).decode()))
  self.reject('/contents/release.json',lambda v:dict(v,content=base64.b64encode(b'x').decode()))
 def test_api_outer_128k_and_duplicate_keys(self):
  def too_big(url,limit):
   if '/git/commits/' in url:return b' '*(q.MAX_API_JSON+1)
   return self.f.fetch(url,limit)
  with self.assertRaises(p.ReleaseError):self.f.run_puller(fetch=too_big)
  def duplicate(url,limit):
   if '/contents/' in url:return b'{"name":"release.json","name":"release.json"}'
   return self.f.fetch(url,limit)
  with self.assertRaises(p.ReleaseError):self.f.run_puller(fetch=duplicate)
  self.f.assert_unchanged()
 def test_decoded_artifact_limits(self):
  for index,limit in ((0,p.MAX_JSON),(1,p.MAX_ARCHIVE)):
   def mutate(v):v['tree'][index]['size']=limit+1;return v
   self.reject('/git/trees/',mutate)
 def test_same_release_only_ref_and_health(self):
  self.f.run_puller();self.f.calls=[]
  self.assertEqual(self.f.run_puller()['status'],'unchanged');self.assertEqual(self.f.calls,[q.REF_URL])
 def test_cache_does_not_hide_page_or_active_drift(self):
  self.f.run_puller();(self.f.site/'index.html').write_bytes(b'other editor')
  self.f.calls=[]
  with self.assertRaises(p.ReleaseError):self.f.run_puller()
  self.assertEqual(self.f.calls,[])
 def test_cache_health_failure_refuses(self):
  self.f.run_puller();self.f.calls=[]
  with self.assertRaises(p.ReleaseError):self.f.run_puller(check=lambda expected:False)
  self.assertEqual(self.f.calls,[q.REF_URL])
 def test_new_release_same_page_updates_active_without_page_replace(self):
  self.f.run_puller();before=(self.f.site/'index.html').stat().st_ino
  with mock.patch.dict(old.__dict__,{'RELEASE':'e'*40}):result=self.f.run_puller()
  self.assertEqual(result['status'],'unchanged');self.assertEqual(before,(self.f.site/'index.html').stat().st_ino)
  self.assertEqual(json.loads((self.f.state/'active.json').read_text())['release_commit'],'e'*40)
  self.f.calls=[]
  with mock.patch.dict(old.__dict__,{'RELEASE':'e'*40}):self.f.run_puller()
  self.assertEqual(self.f.calls,[q.REF_URL])
 def test_same_page_active_failure_and_interrupt_recover_consistently(self):
  for interrupt in (False,True):
   self.f.run_puller();previous=json.loads((self.f.state/'active.json').read_text())
   pull=q.Puller(self.f.site,self.f.state,self.f.backups,self.f.fetch,self.f.healthy);original=pull.write_json;armed=[True]
   def fail(path,value):
    if path.name=='active.json' and armed[0]:
     armed[0]=False
     if interrupt:original(path,value);raise KeyboardInterrupt()
     raise OSError('active metadata failure')
    return original(path,value)
   with mock.patch.dict(old.__dict__,{'RELEASE':'e'*40}),mock.patch.object(pull,'write_json',fail),self.assertRaises(KeyboardInterrupt if interrupt else p.ReleaseError):pull.run()
   if interrupt:self.assertEqual(pull.run()['status'],'recovered_previous')
   self.assertEqual(json.loads((self.f.state/'active.json').read_text()),previous)
   self.assertFalse((self.f.state/'pending.json').exists())
 def test_download_failure_at_all_five_points_keeps_page(self):
  for index in range(5):
   self.f.calls=[]
   def fail(url,limit):
    if len(self.f.calls)==index:raise OSError('offline fail')
    return self.f.fetch(url,limit)
   with self.assertRaises(OSError):self.f.run_puller(fetch=fail)
   self.f.assert_unchanged()
 def test_backoff_persisted_no_sleep_and_no_requests_until_due(self):
  def rate(url,limit):raise q.RateLimited(2000)
  with mock.patch.object(q.time,'time',return_value=1000):result=self.f.run_puller(fetch=rate)
  self.assertEqual(result['status'],'deferred');self.f.assert_unchanged()
  with mock.patch.object(q.time,'time',return_value=1999),mock.patch.object(q.time,'sleep',side_effect=AssertionError('no sleep')):
   result=self.f.run_puller(fetch=lambda *a:(_ for _ in ()).throw(AssertionError('no fetch')))
  self.assertEqual(result['status'],'deferred')
  with mock.patch.object(q.time,'time',return_value=2000):self.assertEqual(self.f.run_puller()['status'],'activated')
 def test_backoff_does_not_hide_state_drift_or_journal_recovery(self):
  self.f.run_puller();(self.f.state/'backoff.json').write_text('{"retry_at":9999999999}')
  active=json.loads((self.f.state/'active.json').read_text());active['page_sha256']='f'*64;(self.f.state/'active.json').write_text(json.dumps(active))
  with self.assertRaises(p.ReleaseError):self.f.run_puller()
 def test_recovery_precedes_rate_backoff(self):
  def interrupt(expected):
   if expected!=p.digest(self.f.old_page):raise KeyboardInterrupt()
   return True
  with self.assertRaises(KeyboardInterrupt):self.f.run_puller(check=interrupt)
  (self.f.state/'backoff.json').write_text('{"retry_at":9999999999}');self.f.calls=[]
  self.assertEqual(self.f.run_puller()['status'],'recovered_previous');self.assertEqual(self.f.calls,[])
 def test_backoff_symlink_or_bad_schema_refused(self):
  path=self.f.state/'backoff.json'
  for data in ('{"retry_at":true}','{"retry_at":1,"url":"evil"}'):
   path.write_text(data)
   with self.assertRaises(p.ReleaseError):self.f.run_puller()
  path.unlink();path.symlink_to(self.f.site/'index.html')
  with self.assertRaises(OSError):self.f.run_puller()
 def test_rate_limit_headers_seconds_date_reset_fallback(self):
  self.assertEqual(q.retry_deadline({'Retry-After':'120','X-RateLimit-Reset':'1500'},1000),1500)
  self.assertEqual(q.retry_deadline({'Retry-After':'Thu, 01 Jan 1970 00:30:00 GMT'},1000),1800)
  self.assertEqual(q.retry_deadline({},1000),4600)
 def test_fetch_http_403_429_are_deferred_and_redirect_never_followed(self):
  for status in (403,429):
   error=urllib.error.HTTPError(q.REF_URL,status,'test',{'Retry-After':'120'},io.BytesIO(b'not output'))
   opener=mock.MagicMock();opener.open.side_effect=error
   with mock.patch.object(q.urllib.request,'build_opener',return_value=opener),mock.patch.object(q.time,'time',return_value=1000),self.assertRaises(q.RateLimited) as caught:q.fetch_fixed(q.REF_URL,p.MAX_JSON)
   self.assertEqual(caught.exception.retry_at,1120)
  self.assertIsNone(q.NoRedirect().redirect_request(None,None,302,'',{},'https://raw.githubusercontent.com/anything'))
  error=urllib.error.HTTPError(q.REF_URL,302,'test',{'Location':'https://evil.invalid/'},io.BytesIO())
  opener=mock.MagicMock();opener.open.side_effect=error
  with mock.patch.object(q.urllib.request,'build_opener',return_value=opener),self.assertRaises(p.ReleaseError):q.fetch_fixed(q.REF_URL,p.MAX_JSON)
  self.assertEqual(opener.open.call_count,1)
 def test_transport_tls_accept_no_auth_and_outer_limit(self):
  opener=mock.MagicMock();response=opener.open.return_value.__enter__.return_value;response.status=200;response.read.return_value=b'{}'
  with mock.patch.object(q.urllib.request,'build_opener',return_value=opener) as builder:
   self.assertEqual(q.fetch_fixed(q.REF_URL,p.MAX_JSON),b'{}')
  handlers=builder.call_args[0];self.assertIsInstance(handlers[0],q.NoRedirect);context=handlers[1]._context
  self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,q.ssl.CERT_REQUIRED)
  request=opener.open.call_args[0][0];self.assertEqual(request.get_header('Accept'),'application/vnd.github+json');self.assertIsNone(request.get_header('Authorization'))
  response.read.return_value=b'x'*(q.MAX_API_JSON+1)
  with mock.patch.object(q.urllib.request,'build_opener',return_value=opener),self.assertRaises(p.ReleaseError):q.fetch_fixed(q.REF_URL,q.MAX_API_JSON)
 def test_url_allowlist_rejects_repo_ref_path_mixing(self):
  urls=[q.API+'/contents/index.html?ref='+old.RELEASE,q.API+'/contents/release.json?ref=main',q.API+'/git/trees/main',q.API+'/git/commits/'+old.RELEASE+'?extra=1',q.API.replace('dziiiii','other')+'/git/commits/'+old.RELEASE,'https://raw.githubusercontent.com/'+p.REPO+'/'+old.RELEASE+'/release.json']
  with mock.patch.object(q.urllib.request,'build_opener',side_effect=AssertionError('no network')):
   for url in urls:
    with self.subTest(url=url),self.assertRaises(p.ReleaseError):q.fetch_fixed(url,q.MAX_API_JSON)
