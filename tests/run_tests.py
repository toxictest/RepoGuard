#!/usr/bin/env python3
"""One-shot development tests. Auditor runtime does not require Python.
Fixtures: real git repositories, controlled localhost HTTP server, Gitleaks stub.
Optionally validate a real Gitleaks binary via REPOGUARD_TEST_GITLEAKS.
"""
import os, pathlib, tempfile, subprocess, json, threading, http.server, shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'repoguard.sh'
passed=0

def check(label,cond):
    global passed
    if not cond: raise AssertionError(label)
    passed+=1;print('PASS',label)

def command(*args,env=None):
    return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=True).stdout.strip()

with tempfile.TemporaryDirectory(prefix='repoguard-tests.') as td:
    t=pathlib.Path(td); seq=0
    def run(args,env=None,expect=0):
        global seq
        seq+=1;dest=t/('report-'+str(seq))
        r=subprocess.run([str(SCRIPT),*map(str,args),'-o',str(dest),'--no-color'],text=True,capture_output=True,env=env,timeout=90)
        check('exit '+str(seq),r.returncode==expect)
        if expect==2: return None,r
        j=json.loads((dest/'git_audit_report.json').read_text());text=(dest/'git_audit_summary.txt').read_text()
        check('valid JSON/text '+str(seq),j['tool']=='RepoGuard' and '\x1b' not in text)
        return j,r
    def save_sample(label):
        if os.environ.get('REPOGUARD_WRITE_SAMPLES')=='1':
            dest=ROOT/'sample-output'/label;dest.mkdir(parents=True,exist_ok=True)
            for name in ('git_audit_report.json','git_audit_summary.txt'):
                shutil.copyfile(t/('report-'+str(seq))/name,dest/name)
    repo=t/'repo';repo.mkdir()
    command('git','init','-q','-b','main',str(repo))
    def git(*args):return command('git','-C',str(repo),*args)
    git('config','user.name','Fixture Developer');git('config','user.email','dev@internal.example')
    (repo/'README').write_text('safe fixture\n');git('add','.');git('commit','-qm','initial')
    clean=git('rev-parse','HEAD')
    j,_=run(['-r',repo,'--scanner','native'])
    check('clean native history',j['verdict']=='CLEAN_WITHIN_SCOPE')
    secret='fixture-OAUTH-value-79362815'
    (repo/'.env').write_text('OAUTH_SECRET="'+secret+'"\nDATABASE_URL="postgres://fixture:dummy-password@db.invalid/app"\n')
    (repo/'token.txt').write_text('GITHUB_TOKEN="ghp_4k9V7m2Q8s6T3w5R1x0Y9z4B2n8C7d6E5f3A"\n')
    (repo/'id_key').write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nTEST-ONLY-NOT-A-REAL-KEY\n')
    (repo/'staging.yaml').write_text('host: staging.invalid\n')
    git('add','.');git('commit','-qm','fake secrets for tests');leaked=git('rev-parse','HEAD')
    (repo/'.env').unlink();(repo/'id_key').unlink();(repo/'token.txt').unlink();git('add','-A');git('commit','-qm','remove fake credentials')
    git('checkout','-qb','feature/unmerged');(repo/'feature.txt').write_text('feature\n');git('add','.');git('commit','-qm','feature');git('checkout','-q','main')
    # A curl stub fails if accidentally called in local mode.
    bins=t/'bin';bins.mkdir()
    (bins/'curl').write_text('#!/bin/sh\ntouch "'+str(t/'NETWORK_CALLED')+'"\nexit 98\n');(bins/'curl').chmod(0o755)
    env=os.environ|{'PATH':str(bins)+':'+os.environ['PATH']}
    j,r=run(['-r',repo,'--scanner','native'],env)
    check('removed secrets found',any(f.get('commit')==leaked and f.get('state')=='SECRET' for f in j['findings']))
    rules={f.get('rule') for f in j['findings']}
    check('private key marker','private-key' in rules)
    check('database credential URI','database-credential-uri' in rules)
    check('OAuth secret','credential-assignment' in rules)
    check('env history','env-file-history' in rules)
    check('staging history','staging-config-history' in rules)
    check('author domain',any(f.get('domain')=='internal.example' for f in j['findings']))
    check('unmerged feature branch',any(f.get('ref')=='refs/heads/feature/unmerged' for f in j['findings']))
    check('redaction',secret not in json.dumps(j)+r.stdout+r.stderr)
    check('no remote calls locally',not (t/'NETWORK_CALLED').exists())
    check('no repository edits',not git('status','--porcelain'))
    check('secret verdict is yellow-class',j['verdict']=='SECRETS_FOUND')
    save_sample('local-native')
    run(['-r',repo,'--scanner','native','--strict'],env,expect=1)
    run(['-r',repo,'--scanner','native','--base','not-a-ref'],env,expect=2)
    # Gitleaks adapter with intentionally unredacted output tests field allowlisting.
    gl=bins/'gitleaks'
    gl.write_text('''#!/usr/bin/env python3
import sys,json,os
assert os.environ['GIT_ALLOW_PROTOCOL']==''
assert '--redact=100' in sys.argv
p=sys.argv[sys.argv.index('--report-path')+1]
json.dump([{'RuleID':'fixture-rule','Commit':'abc123','File':'file.txt','StartLine':7,'Secret':'DO-NOT-EXPORT-ME','Match':'DO-NOT-EXPORT-ME'}],open(p,'w'))
sys.exit(10)
''');gl.chmod(0o755)
    j,r=run(['-r',repo,'--scanner','gitleaks'],env)
    check('gitleaks integration',j['scanner']=='gitleaks+native' and any(f.get('rule')=='fixture-rule' for f in j['findings']))
    check('gitleaks field redaction','DO-NOT-EXPORT-ME' not in json.dumps(j)+r.stdout+r.stderr)
    gl.write_text('#!/bin/sh\nexit 2\n')
    j,_=run(['-r',repo,'--scanner','gitleaks'],env)
    check('gitleaks error not clean',any(f.get('state')=='INCOMPLETE' for f in j['findings']))
    check('native fallback retained',j['summary']['secret_findings']>0)
    # Empty and bare repositories, shallow clone coverage.
    empty=t/'empty';command('git','init','-q',str(empty))
    j,_=run(['-r',empty,'--scanner','native']);check('empty repo',any(f['state']=='EMPTY_REPOSITORY' for f in j['findings']))
    bare=t/'bare';command('git','clone','--bare','-q',str(repo),str(bare))
    j,_=run(['-r',bare,'--scanner','native']);check('bare repo',j['summary']['secret_findings']>0)
    shallow=t/'shallow';command('git','clone','-q','--depth','1',repo.as_uri(),str(shallow))
    j,_=run(['-r',shallow,'--scanner','native']);check('shallow coverage warning',any('Shallow clone' in f['detail'] for f in j['findings']))
    # No working tree scan: commit history only.
    git('checkout','--detach','-q',clean)
    (repo/'untracked.env').write_text('OAUTH_SECRET="untracked-not-scanned"')
    j,_=run(['-r',repo,'--scanner','native']);check('untracked excluded',not any(f.get('file')=='untracked.env' for f in j['findings']))
    git('checkout','-q','main')
    # HTTP server with no external network dependency.
    requests=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_HEAD(self):self.reply(True)
        def do_GET(self):self.reply(False)
        def reply(self,head):
            requests.append((self.command,self.path));status=404;body=b'not found'
            group=self.path.split('/')[1];p='/'+'/'.join(self.path.split('/')[2:])
            if group=='exposed':
                mapping={'/.git/HEAD':b'ref: refs/heads/main\n','/.git/config':b'[core]\n repositoryformatversion = 0\n bare = false\n[remote "origin"]\n url = https://fake:private-token@git.invalid/repo\n','/.gitignore':b'node_modules/\n.env\n','/.svn/entries':b'<?xml version="1.0"?><wc-entries><entry name="" kind="dir" /></wc-entries>'}
                if p in mapping:status=200;body=mapping[p]
            elif group=='waf':status=200;body=b'<html>Welcome ref: refs/heads/main</html>'
            elif group=='catchall':status=200;body=b'ref: refs/heads/main\n'
            elif group=='redirect':status=302;body=b'redirect'
            elif group=='denied':status=403;body=b'Forbidden'
            elif group=='detached' and p=='/.git/HEAD':status=200;body=b'a'*40+b'\n'
            elif group=='head405' and p=='/.git/HEAD':status=405 if head else 200;body=b'ref: refs/heads/main\r\n'
            elif group=='oversize':status=200;body=b'x'*1048577
            elif group=='legacy' and p=='/.svn/entries':status=200;body=b'10\n\ndir\n123\n'
            self.send_response(status);self.send_header('Content-Length',str(len(body)))
            if status==302:self.send_header('Location','https://must-not-follow.invalid/')
            self.end_headers()
            if not head:
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:'+str(server.server_port)
    try:
        j,r=run(['-u',base+'/exposed/.git/HEAD'])
        check('three verified VCS exposures',j['summary']['exposures']==3)
        save_sample('remote-fixture')
        check('gitignore not an exposed git proof',any(f['path']=='/.gitignore' and f['state']=='PUBLIC_IGNORE_FILE' for f in j['findings']))
        check('config values never exported','private-token' not in json.dumps(j)+r.stdout+r.stderr)
        check('HEAD requests performed',any(m=='HEAD' for m,p in requests))
        check('no objects or pack fetches',not any('/objects' in p or '/pack' in p for m,p in requests))
        for group in ['waf','catchall','denied','missing']:
            j,_=run(['-u',base+'/'+group]);check('no false exposure '+group,j['summary']['exposures']==0)
        for group in ['detached','head405','legacy']:
            j,_=run(['-u',base+'/'+group]);check('verify '+group,j['summary']['exposures']==1)
        j,_=run(['-u',base+'/redirect']);check('redirect inconclusive',j['verdict']=='REVIEW')
        j,_=run(['-u',base+'/oversize']);check('bounded body inconclusive',j['verdict']=='REVIEW')
        listing=t/'urls.txt';listing.write_text('# fixture\n'+base+'/exposed\n'+base+'/exposed/\n'+base+'/waf\n')
        j,_=run(['-l',listing,'-t','2']);check('list deduplicated',len(j['targets'])==2)
        check('parallel results retained',len(j['findings'])==8)
        run(['-u',base+'/exposed','--strict'],expect=1)
    finally:server.shutdown();server.server_close()
    j,_=run(['-u',base+'/offline','--timeout','1']);check('connection failure not clean',j['verdict']=='REVIEW')
    for args in [[],['-u'],['--bogus'],['-u','file:///etc/passwd'],['-u','https://user:pass@host'],['-u','https://host?token=x'],['-u','https://host','-r',repo],['-r',t/'missing'],['-l',t/'missing'],['-u','https://host','-t','0']]:
        run(args,expect=2)
    real=os.environ.get('REPOGUARD_TEST_GITLEAKS')
    if real:
        rb=t/'realbin';rb.mkdir();(rb/'gitleaks').symlink_to(real)
        realenv=os.environ|{'PATH':str(rb)+':'+os.environ['PATH']}
        j,_=run(['-r',repo,'--scanner','gitleaks'],realenv)
        check('real Gitleaks completed',not any(f.get('state')=='INCOMPLETE' for f in j['findings']))
        check('real Gitleaks detected fixture',any(f.get('scanner')=='gitleaks' for f in j['findings']))
        save_sample('local-gitleaks')
print(f'\nPASS {passed} / FAIL 0')
