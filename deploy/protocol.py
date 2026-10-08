"""Trusted, installed protocol. Static data only; never extractall or execute releases."""
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

REPO = 'dziiiii/cloud-web-demo'
BRANCH = 'nw6-release'
MAX_JSON = 8192
MAX_ARCHIVE = 65536
MAX_EXPANDED_TAR = 262144
MAX_HTML = 65536
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')

class ReleaseError(ValueError): pass

def digest(data): return hashlib.sha256(data).hexdigest()
def parse_json(data,limit=MAX_JSON):
    if len(data) > limit: raise ReleaseError('JSON size limit')
    def unique(pairs):
        result = {}
        for key,value in pairs:
            if key in result: raise ReleaseError('duplicate JSON key')
            result[key] = value
        return result
    try: return json.loads(data.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error: raise ReleaseError('invalid JSON') from error

def render(commit):
    # Build-side fixed repository entry only. The installed puller never calls this.
    if not isinstance(commit,str) or not SHA.fullmatch(commit):raise ReleaseError('full source SHA required')
    source=Path(__file__).resolve().parents[1]/'index.html'
    if source.is_symlink() or not source.is_file():raise ReleaseError('regular fixed entry required')
    with source.open('rb') as stream:page=stream.read(MAX_HTML+1)
    if not 1 <= len(page) <= MAX_HTML:raise ReleaseError('HTML limit')
    return page

def validate_manifest(value):
    if not isinstance(value,dict) or set(value) != {'schema','source_sha','archive_sha256','archive_bytes','files'}:
        raise ReleaseError('manifest schema')
    if type(value['schema']) is not int or value['schema'] != 1: raise ReleaseError('schema version')
    if not isinstance(value['archive_sha256'],str) or not DIGEST.fullmatch(value['archive_sha256']):raise ReleaseError('digest format')
    if type(value['archive_bytes']) is not int or not 1 <= value['archive_bytes'] <= MAX_ARCHIVE:raise ReleaseError('archive limit')
    if not isinstance(value['source_sha'],str) or not SHA.fullmatch(value['source_sha']):raise ReleaseError('source SHA')
    files=value['files']
    if not isinstance(files,dict) or set(files) != {'index.html'}:raise ReleaseError('only index.html allowed')
    entry=files['index.html']
    if not isinstance(entry,dict) or set(entry)!={'sha256','bytes'}:raise ReleaseError('file schema')
    if not isinstance(entry['sha256'],str) or not DIGEST.fullmatch(entry['sha256']):raise ReleaseError('file digest')
    if type(entry['bytes']) is not int or not 1 <= entry['bytes'] <= MAX_HTML:raise ReleaseError('HTML limit')
    return value

def unpack(manifest, compressed):
    validate_manifest(manifest)
    if len(compressed) != manifest['archive_bytes'] or digest(compressed) != manifest['archive_sha256']:
        raise ReleaseError('archive integrity')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed),mode='rb') as stream:
            raw=stream.read(MAX_EXPANDED_TAR+1)
        if len(raw)>MAX_EXPANDED_TAR:raise ReleaseError('expanded tar limit')
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            members=archive.getmembers()
            if len(members)!=1:raise ReleaseError('exactly one regular member required')
            member=members[0]
            # Exact allowlist rejects ../, absolute paths, backslashes and duplicate names.
            if member.name!='index.html' or member.type not in (tarfile.REGTYPE,tarfile.AREGTYPE):
                raise ReleaseError('unsafe path or link')
            if member.pax_headers or member.sparse:raise ReleaseError('unsupported tar metadata')
            if member.size!=manifest['files']['index.html']['bytes'] or member.size>MAX_HTML:
                raise ReleaseError('member size')
            stream=archive.extractfile(member)
            page=stream.read(MAX_HTML+1)
    except (OSError,EOFError,tarfile.TarError) as error:raise ReleaseError('invalid archive') from error
    if len(page)!=manifest['files']['index.html']['bytes'] or digest(page)!=manifest['files']['index.html']['sha256']:raise ReleaseError('HTML integrity')
    return page

def build(commit, page=None):
    if not isinstance(commit,str) or not SHA.fullmatch(commit):raise ReleaseError('full source SHA required')
    if page is None:page=render(commit)
    if not isinstance(page,bytes) or not 1 <= len(page) <= MAX_HTML:raise ReleaseError('HTML limit')
    output=io.BytesIO()
    with gzip.GzipFile(fileobj=output,mode='wb',mtime=0,filename='') as gz:
        with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            member=tarfile.TarInfo('index.html');member.size=len(page);member.mode=0o644
            member.mtime=0;member.uid=member.gid=0;member.uname=member.gname=''
            archive.addfile(member,io.BytesIO(page))
    compressed=output.getvalue()
    manifest={'schema':1,'source_sha':commit,'archive_sha256':digest(compressed),'archive_bytes':len(compressed),
              'files':{'index.html':{'sha256':digest(page),'bytes':len(page)}}}
    unpack(manifest,compressed)
    return manifest,compressed
