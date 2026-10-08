"""Runner-only publisher. Fixed repo/ref; normal fast-forward push, never force.
The server never downloads or executes this program.
"""
import argparse,base64,json,os,re,subprocess,tempfile
from pathlib import Path
from deploy.protocol import REPO,BRANCH,parse_json,unpack

def git(args,cwd,env,allowed=(0,)):
    result=subprocess.run(['git']+args,cwd=str(cwd),env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode not in allowed:raise RuntimeError('git operation failed: '+args[0])
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',required=True,type=Path);p.add_argument('--expected-digest',required=True);a=p.parse_args()
    if os.environ.get('GITHUB_REPOSITORY')!=REPO or os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch':
        raise SystemExit('only manual main workflow in fixed repository may publish')
    if set(x.name for x in a.directory.iterdir())!={'release.json','site.tar.gz'}:raise SystemExit('artifact directory allowlist')
    manifest=parse_json((a.directory/'release.json').read_bytes());archive=(a.directory/'site.tar.gz').read_bytes();unpack(manifest,archive)
    if manifest['archive_sha256']!=a.expected_digest:raise SystemExit('build job digest mismatch')
    if manifest['source_sha']!=os.environ.get('GITHUB_SHA'):raise SystemExit('source SHA mismatch')
    token=os.environ.get('GH_TOKEN','')
    if not token:raise SystemExit('ephemeral workflow token required')
    # Token lives only in environment, never command args, git config on disk or URL.
    env=os.environ.copy();env['GIT_TERMINAL_PROMPT']='0'
    env['GIT_CONFIG_COUNT']='1';env['GIT_CONFIG_KEY_0']='http.https://github.com/.extraheader'
    env['GIT_CONFIG_VALUE_0']='AUTHORIZATION: basic '+base64.b64encode(('x-access-token:'+token).encode()).decode()
    with tempfile.TemporaryDirectory(prefix='nw6-release-') as name:
        directory=Path(name);git(['init','--quiet'],directory,env)
        git(['remote','add','origin','https://github.com/'+REPO+'.git'],directory,env)
        ref='refs/heads/'+BRANCH
        existing=git(['ls-remote','--exit-code','origin',ref],directory,env,allowed=(0,2))
        if existing.returncode==0:
            line=existing.stdout.decode().strip().split('\t')
            if len(line)!=2 or not re.fullmatch('[0-9a-f]{40}',line[0]) or line[1]!=ref:raise RuntimeError('unexpected remote ref')
            git(['fetch','--depth=1','--no-tags','origin',ref],directory,env)
            actual=git(['rev-parse','FETCH_HEAD'],directory,env).stdout.decode().strip()
            if actual!=line[0]:raise RuntimeError('release branch changed during fetch; rerun manually')
            git(['checkout','-B',BRANCH,'FETCH_HEAD'],directory,env)
            git(['rm','-r','--ignore-unmatch','.'],directory,env)
        else:git(['checkout','--orphan',BRANCH],directory,env)
        (directory/'release.json').write_bytes((a.directory/'release.json').read_bytes())
        (directory/'site.tar.gz').write_bytes(archive)
        git(['add','release.json','site.tar.gz'],directory,env)
        git(['-c','user.name=NW6 release workflow','-c','user.email=noreply@github.com','commit','--allow-empty','-m','Minimal static release '+manifest['source_sha']],directory,env)
        git(['push','origin','HEAD:'+ref],directory,env)
        print('Published only two static artifact files to '+BRANCH)
if __name__=='__main__':main()
