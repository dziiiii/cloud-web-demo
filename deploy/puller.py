"""Installed by an approved administrator; Python3.6, no sudo or subprocess.
Fetch only fixed repository and branch. Never run/import downloaded code.
"""
import base64
import binascii
import hashlib
import time
import email.utils
import urllib.error
import fcntl
import http.client
import json
import os
import socket
import stat
import ssl
import tempfile
import uuid
import urllib.request
from pathlib import Path
from deploy.protocol import (REPO,BRANCH,MAX_JSON,MAX_ARCHIVE,MAX_HTML,SHA,DIGEST,ReleaseError,digest,parse_json,validate_manifest,unpack)

SITE=Path('/var/www/haoduoo/sites/nw6')
STATE=Path('/var/lib/nw6-static/state')
BACKUPS=Path('/var/lib/nw6-static/backups')
HEALTH_HOST='haoduoo.com'
HEALTH_PATH='/nw6'
REF_URL='https://api.github.com/repos/'+REPO+'/git/ref/heads/'+BRANCH
MAX_BACKUPS=20

API='https://api.github.com/repos/'+REPO
MAX_API_JSON=131072
ARTIFACT_LIMITS={'release.json':MAX_JSON,'site.tar.gz':MAX_ARCHIVE}

class RateLimited(ReleaseError):
    def __init__(self,retry_at):
        self.retry_at=retry_at
        super().__init__('GitHub rate limited; retry deferred')

def retry_deadline(headers,now):
    deadlines=[now+60]
    supplied=False
    retry=headers.get('Retry-After','')
    if retry.isdigit():deadlines.append(now+int(retry));supplied=True
    elif retry:
        parsed=email.utils.parsedate_tz(retry)
        if parsed is not None:deadlines.append(int(email.utils.mktime_tz(parsed)));supplied=True
    reset=headers.get('X-RateLimit-Reset','')
    if reset.isdigit():deadlines.append(int(reset));supplied=True
    if not supplied:deadlines.append(now+3600)
    return max(deadlines)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def fetch_fixed(url,limit):
    # URL response fields are never followed; only internally pinned API endpoints.
    valid=url==REF_URL
    for kind in ('commits','trees'):
        prefix=API+'/git/'+kind+'/'
        if url.startswith(prefix):valid=bool(SHA.fullmatch(url[len(prefix):]))
    for name in ARTIFACT_LIMITS:
        prefix=API+'/contents/'+name+'?ref='
        if url.startswith(prefix):valid=bool(SHA.fullmatch(url[len(prefix):]))
    if not valid or type(limit) is not int or not 1<=limit<=MAX_API_JSON:raise ReleaseError('URL outside fixed protocol')
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request=urllib.request.Request(url,headers={'User-Agent':'nw6-static-puller-v2','Accept':'application/vnd.github+json'})
    try:
        with opener.open(request,timeout=10) as response:
            if response.status!=200:raise ReleaseError('download status')
            data=response.read(limit+1)
    except urllib.error.HTTPError as error:
        try:
            if error.code in (403,429):raise RateLimited(retry_deadline(error.headers,int(time.time()))) from error
            raise ReleaseError('GitHub HTTP status '+str(error.code)) from error
        finally:error.close()
    if len(data)>limit:raise ReleaseError('download size limit')
    return data

def blob_sha(data):
    return hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()

def api_json(fetch,url):return parse_json(fetch(url,MAX_API_JSON),MAX_API_JSON)

def read_release(fetch,commit):
    if not isinstance(commit,str) or not SHA.fullmatch(commit):raise ReleaseError('fixed complete release commit required')
    value=api_json(fetch,API+'/git/commits/'+commit)
    if not isinstance(value,dict) or value.get('sha')!=commit:raise ReleaseError('immutable commit mismatch')
    tree=value.get('tree')
    if not isinstance(tree,dict) or not isinstance(tree.get('sha'),str) or not SHA.fullmatch(tree['sha']):raise ReleaseError('commit tree SHA')
    tree_sha=tree['sha']
    value=api_json(fetch,API+'/git/trees/'+tree_sha)
    if not isinstance(value,dict) or value.get('sha')!=tree_sha or value.get('truncated') is not False or not isinstance(value.get('tree'),list):raise ReleaseError('root tree mismatch or truncation')
    entries={}
    for item in value['tree']:
        if not isinstance(item,dict) or not isinstance(item.get('path'),str) or item.get('path') not in ARTIFACT_LIMITS or item['path'] in entries:raise ReleaseError('unexpected root entry')
        name=item['path']
        if item.get('mode')!='100644' or item.get('type')!='blob':raise ReleaseError('ordinary root blob required')
        if not isinstance(item.get('sha'),str) or not SHA.fullmatch(item['sha']):raise ReleaseError('blob SHA format')
        if type(item.get('size')) is not int or not 1<=item['size']<=ARTIFACT_LIMITS[name]:raise ReleaseError('blob size limit')
        entries[name]=item
    if set(entries)!=set(ARTIFACT_LIMITS):raise ReleaseError('exact two root blobs required')
    payloads={}
    for name in ('release.json','site.tar.gz'):
        entry=entries[name]
        value=api_json(fetch,API+'/contents/'+name+'?ref='+commit)
        if not isinstance(value,dict) or value.get('name')!=name or value.get('path')!=name or value.get('type')!='file' or value.get('encoding')!='base64':raise ReleaseError('Contents identity or encoding')
        if value.get('sha')!=entry['sha'] or type(value.get('size')) is not int or value['size']!=entry['size']:raise ReleaseError('Contents blob identity or size')
        content=value.get('content')
        if not isinstance(content,str):raise ReleaseError('Contents content type')
        try:
            encoded=content.encode('ascii').replace(b'\n',b'')  # GitHub LF wrapping only.
            data=base64.b64decode(encoded,validate=True)
        except (UnicodeError,ValueError,binascii.Error) as error:raise ReleaseError('strict ASCII base64 required') from error
        if base64.b64encode(data)!=encoded:raise ReleaseError('noncanonical base64')
        if len(data)!=entry['size'] or len(data)>ARTIFACT_LIMITS[name] or blob_sha(data)!=entry['sha']:raise ReleaseError('decoded blob integrity')
        payloads[name]=data
    manifest=validate_manifest(parse_json(payloads['release.json']))
    return manifest,unpack(manifest,payloads['site.tar.gz'])

class LocalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # TLS verifies the real hostname; TCP stays on localhost. No redirects.
        plain=socket.create_connection(('127.0.0.1',443),timeout=self.timeout)
        try:self.sock=self._context.wrap_socket(plain,server_hostname=HEALTH_HOST)
        except Exception:
            plain.close();raise

def health(expected):
    connection=LocalHTTPS(HEALTH_HOST,timeout=10,context=ssl.create_default_context())
    try:
        connection.request('GET',HEALTH_PATH,headers={'Host':HEALTH_HOST,'Cache-Control':'no-cache'})
        response=connection.getresponse();body=response.read(MAX_HTML+1)
        return response.status==200 and len(body)<=MAX_HTML and digest(body)==expected
    finally:connection.close()

class Puller:
    def __init__(self,site,state,backups,fetch,check):
        self.site=Path(site);self.state=Path(state);self.backups=Path(backups)
        self.page=self.site/'index.html';self.fetch=fetch;self.check=check
    def validate_dirs(self):
        for directory in (self.site,self.state,self.backups):
            if not directory.is_dir() or directory.is_symlink() or directory.resolve()!=directory.absolute():
                raise ReleaseError('approved real directories required')
    def read_bounded(self,path,limit,require_page_mode=False):
        fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ReleaseError('bounded regular file required')
            if require_page_mode and info.st_mode & 0o777 != 0o644:raise ReleaseError('page mode must be 0644')
            with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(limit+1)
            if len(data)>limit:raise ReleaseError('file grew beyond limit')
            return data
        finally:os.close(fd)
    def read_page(self):
        if not self.page.is_file() or self.page.is_symlink():raise ReleaseError('regular current page required')
        return self.read_bounded(self.page,MAX_HTML,True)
    def sync_dir(self,directory):
        fd=os.open(str(directory),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def atomic_page(self,content,expected):
        if digest(self.read_page())!=expected:raise ReleaseError('page drift; refusing overwrite')
        fd,name=tempfile.mkstemp(prefix='.nw6-',suffix='.tmp',dir=str(self.site))
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(content);stream.flush();os.fsync(stream.fileno())
                os.fchmod(stream.fileno(),0o644)
            if digest(self.read_page())!=expected:raise ReleaseError('page changed during staging')
            os.replace(name,str(self.page));self.sync_dir(self.site)
        finally:
            if os.path.exists(name):os.unlink(name)
    def write_json(self,path,value):
        if path.is_symlink():raise ReleaseError('unsafe state file')
        fd,name=tempfile.mkstemp(prefix='.state-',dir=str(self.state))
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(value,stream,sort_keys=True)
                stream.flush();os.fsync(stream.fileno())
            os.replace(name,str(path));self.sync_dir(self.state)
        finally:
            if os.path.exists(name):os.unlink(name)
    def save_backup(self,content):
        name='old-'+digest(content)+'.html';path=self.backups/name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_HTML or self.read_bounded(path,MAX_HTML)!=content:
                raise ReleaseError('unsafe backup or backup drift')
        else:
            if len(list(self.backups.iterdir()))>=MAX_BACKUPS:raise ReleaseError('backup capacity reached; administrator review required')
            fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(content);stream.flush();os.fsync(stream.fileno())
            self.sync_dir(self.backups)
        return name
    def read_active(self,expected):
        path=self.state/'active.json'
        if not path.exists() and not path.is_symlink():return None
        value=parse_json(self.read_bounded(path,MAX_JSON))
        self.validate_active(value)
        if value['page_sha256']!=expected:raise ReleaseError('active page drift; administrator review required')
        return value
    def validate_active(self,value):
        if not isinstance(value,dict) or set(value)!={'source_sha','release_commit','page_sha256'}:raise ReleaseError('invalid active state')
        if not isinstance(value['page_sha256'],str) or not DIGEST.fullmatch(value['page_sha256']):raise ReleaseError('invalid active digest')
        for key in ('source_sha','release_commit'):
            if value[key] is not None and (not isinstance(value[key],str) or not SHA.fullmatch(value[key])):raise ReleaseError('invalid active commit')
    def recover(self):
        pending=self.state/'pending.json'
        if not pending.exists() and not pending.is_symlink():return None
        journal=parse_json(self.read_bounded(pending,MAX_JSON))
        if not isinstance(journal,dict) or set(journal)!={'old_digest','new_digest','backup','old_active','new_active'}:raise ReleaseError('invalid journal')
        for key in ('old_digest','new_digest'):
            if not isinstance(journal[key],str) or not DIGEST.fullmatch(journal[key]):raise ReleaseError('invalid journal digest')
        for key in ('old_active','new_active'):self.validate_active(journal[key])
        if journal['old_active']['page_sha256']!=journal['old_digest'] or journal['new_active']['page_sha256']!=journal['new_digest']:raise ReleaseError('journal state mismatch')
        if journal['backup']!='old-'+journal['old_digest']+'.html':raise ReleaseError('unsafe recovery backup')
        original=self.read_bounded(self.backups/journal['backup'],MAX_HTML)
        if digest(original)!=journal['old_digest']:raise ReleaseError('backup drift')
        active_path=self.state/'active.json'
        if active_path.exists() or active_path.is_symlink():
            active=parse_json(self.read_bounded(active_path,MAX_JSON))
            if active not in (journal['old_active'],journal['new_active']):raise ReleaseError('active changed; refusing recovery')
        current=digest(self.read_page())
        if current==journal['new_digest'] and current!=journal['old_digest']:self.atomic_page(original,current)
        elif current!=journal['old_digest']:raise ReleaseError('journal page drift; refusing overwrite')
        # Journal stays until BOTH page and old metadata have been persisted.
        self.write_json(active_path,journal['old_active'])
        pending.unlink();self.sync_dir(self.state)
        try:restored=self.check(journal['old_digest'])
        except Exception:restored=False
        return {'status':'recovered_previous','previous_health':bool(restored)}
    def run(self):
        self.validate_dirs();self.read_page()
        fd=os.open(str(self.state/'pull.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return {'status':'busy'}
            return self.locked()
        finally:os.close(fd)
    def locked(self):
        recovered=self.recover()
        if recovered is not None:return recovered
        original=self.read_page();old_digest=digest(original)
        previous_active=self.read_active(old_digest)  # Never let backoff/cache hide current state drift.
        path=self.state/'backoff.json'
        if path.exists() or path.is_symlink():
            state=parse_json(self.read_bounded(path,MAX_JSON))
            if not isinstance(state,dict) or set(state)!={'retry_at'} or type(state['retry_at']) is not int or state['retry_at']<0:raise ReleaseError('invalid backoff state')
            if int(time.time())<state['retry_at']:
                if not self.check(old_digest):raise ReleaseError('deferred current page health failed')
                return {'status':'deferred','retry_at':state['retry_at']}
        try:return self.download_and_activate()
        except RateLimited as error:
            if digest(self.read_page())!=old_digest or self.read_active(old_digest)!=previous_active:raise ReleaseError('rate limited page/state drift; refusing cache write')
            self.write_json(path,{'retry_at':error.retry_at})
            return {'status':'deferred','retry_at':error.retry_at,'reason':'GitHub rate limited; current page retained'}

    def download_and_activate(self):
        recovered=self.recover()
        if recovered is not None:return recovered
        original=self.read_page();old_digest=digest(original)
        old_active=self.read_active(old_digest)
        if old_active is None:old_active={'source_sha':None,'release_commit':None,'page_sha256':old_digest}
        ref=parse_json(self.fetch(REF_URL,MAX_JSON))
        obj=ref.get('object',{}) if isinstance(ref,dict) else {}
        commit=obj.get('sha')
        if obj.get('type')!='commit' or not isinstance(commit,str) or not SHA.fullmatch(commit):raise ReleaseError('release ref must resolve to full commit SHA')
        if old_active['release_commit']==commit:
            if not self.check(old_digest):raise ReleaseError('cached current page health failed')
            if digest(self.read_page())!=old_digest or self.read_active(old_digest)!=old_active:raise ReleaseError('cached page/state drift')
            return {'status':'unchanged','source_sha':old_active['source_sha'],'release_commit':commit}
        manifest,page=read_release(self.fetch,commit)
        new_digest=digest(page)
        if not self.check(old_digest):raise ReleaseError('baseline health failed; current page untouched')
        backup=self.save_backup(original)
        pending=self.state/'pending.json'
        new_active={'source_sha':manifest['source_sha'],'release_commit':commit,'page_sha256':new_digest}
        self.write_json(pending,{'old_digest':old_digest,'new_digest':new_digest,'backup':backup,'old_active':old_active,'new_active':new_active})
        try:
            if new_digest!=old_digest:self.atomic_page(page,old_digest)
            elif digest(self.read_page())!=old_digest:raise ReleaseError('same-page drift')
            if not self.check(new_digest):raise ReleaseError('candidate health failed')
            self.write_json(self.state/'active.json',new_active)
            pending.unlink();self.sync_dir(self.state)
        except Exception as error:
            # Recovery checks exact current/backup hashes; never overwrite unrelated changes.
            try:recovery=self.recover()
            except Exception as rollback_error:raise ReleaseError('rollback unconfirmed; administrator review required') from rollback_error
            if recovery is None:
                # Unlink is the logical commit boundary: both page and active were
                # fsynced first. A final directory-fsync failure is uncertain durability,
                # not a rollback. Never claim an old page was restored here.
                self.read_active(digest(self.read_page()))
                raise ReleaseError('commit cleanup durability unconfirmed; page and active retained; administrator review required') from error
            raise ReleaseError('publish failed; previous page restored; health '+('passed' if recovery['previous_health'] else 'unverified')) from error
        return {'status':'unchanged' if new_digest==old_digest else 'activated','source_sha':manifest['source_sha'],'release_commit':commit,'page_sha256':new_digest}

def main():
    try:
        if os.geteuid()==0:raise ReleaseError('must run as approved non-root user')
        program=Path(__file__).resolve().parents[1]
        if program!=Path('/var/lib/nw6-static/program'):raise ReleaseError('approved installed program path required')
        for path in (program,program/'deploy',Path(__file__).resolve(),program/'deploy/protocol.py'):
            info=path.stat()
            if info.st_uid!=0 or info.st_mode & 0o022:raise ReleaseError('program must remain root-owned and not group/world writable')
        result=Puller(SITE,STATE,BACKUPS,fetch_fixed,health).run()
        print(json.dumps(result,sort_keys=True))
    except Exception as error:
        print(json.dumps({'status':'failed','error_type':type(error).__name__,'reason':str(error) if isinstance(error,ReleaseError) else 'operation failed; inspect local state'}))
        raise SystemExit(1)
if __name__=='__main__':main()
