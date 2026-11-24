package scripts_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const target3013FixtureSHA256 = "279dd959aa458e3e4f13899fa90cbd9b8479a262cfe242b83ea4af061f878002"

func target3013FixturePath() string {
	return filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_es_tls_status", "openssl3013_negative_responses.json")
}

func runTarget3013Probe(t *testing.T, mode string) map[string]bool {
	t.Helper()
	fixture, err := os.ReadFile(target3013FixturePath())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(fixture)) != target3013FixtureSHA256 {
		t.Fatal("target 3.0.13 projection identity changed")
	}
	const probe = `
import base64,hashlib,importlib.util,json,re,sys
source,fixture_path,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location('target3013_status',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=json.load(open(fixture_path,'r',encoding='utf-8'))
assert f['format']=='es-p0st-openssl3013-negative-responses/v1'
assert f['source_native_result_sha256']=='41620e727d0f28e40a38f8a8965696274faa57679b3d91555e9becc903b19e34'
assert len(f['cases'])==13 and len(f['native_only_controls'])==3 and len(f['inputs'])==14
assert not any('private key' in name.lower() and not name.startswith('literal:') for name in f['inputs'])
def decoded(b64,size,digest):
    raw=base64.b64decode(b64,validate=True)
    assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
    return raw
inputs={name:decoded(row['bytes_b64'],row['size'],row['sha256']) for name,row in f['inputs'].items()}
cases={row['id']:row for row in f['cases']}
controls={row['id']:row for row in f['native_only_controls']}
assert set(cases)=={'meta_malformed','key_malformed','verify_client_wrong_anchor','verify_client_leaf_expired','verify_client_leaf_future','verify_client_issuer_expired','verify_client_purpose_mismatch','verify_egs_wrong_hostname','verify_egs_wrong_anchor','verify_egs_leaf_expired','verify_egs_leaf_future','verify_egs_issuer_expired','verify_ars_wrong_hostname'}
assert set(controls)=={'pem_malformed','der_malformed','text_malformed'}
for c in list(cases.values())+list(controls.values()):
    decoded(c['stdout_b64'],c['stdout_size'],c['stdout_sha256'])
    decoded(c['stderr_b64'],c['stderr_size'],c['stderr_sha256'])
    assert c['argv'][0]==m.OPENSSL
for c in cases.values():
    assert hashlib.sha256(inputs[c['input_role']]).hexdigest()==c['input_sha256']
    if c['anchor_role'] is not None:
        assert hashlib.sha256(inputs[c['anchor_role']]).hexdigest()==c['anchor_sha256']
def response(c):
    return c['exit'],decoded(c['stdout_b64'],c['stdout_size'],c['stdout_sha256']),decoded(c['stderr_b64'],c['stderr_size'],c['stderr_sha256'])
def consume(c,tuple_override=None,purpose_override=None,hostname_override=None):
    raw=inputs[c['input_role']]
    anchor=inputs[c['anchor_role']] if c['anchor_role'] else None
    value=response(c) if tuple_override is None else tuple_override
    purpose=c['argv'][5] if c['family'].startswith('verify_') else None
    hostname=c['argv'][7] if c['family']=='verify_server' else ''
    if purpose_override is not None: purpose=purpose_override
    if hostname_override is not None: hostname=hostname_override
    expected=[m.OPENSSL,'verify','-trusted',m.TRUST_FD_OPERAND,'-purpose',purpose]
    if hostname: expected+=['-verify_hostname',hostname]
    expected+=['/dev/stdin']
    seen=[];old_run=m.run_fixed;old_open=m.open_fixed_regular
    def fixed(argv,input_bytes=None,anchor_bytes=None):
        seen.append((argv,input_bytes,anchor_bytes))
        assert tuple(argv)==tuple(expected if purpose is not None else c['argv'])
        assert input_bytes==raw and anchor_bytes==anchor
        return value
    m.run_fixed=fixed
    m.open_fixed_regular=lambda path,limit,read_content=True: raw
    try:
        if c['family']=='metadata': result=m.cert_metadata('synthetic')[0]
        elif c['family']=='key_der': result=m.key_pair('synthetic',{'public_key_sha256':'a'*64},'synthetic')
        else: result=m.verify_chain('synthetic',{'sha256':c['anchor_sha256']},{'sha256':c['input_sha256']},anchor,raw,purpose,hostname)
        return len(seen)==1,result['code']
    except m.Incomplete:
        return len(seen)<=1,None
    finally:
        m.run_fixed=old_run;m.open_fixed_regular=old_open
checks={}
if mode=='malformed':
    for ident in ('meta_malformed','key_malformed'):
        c=cases[ident];native=response(c);seen,code=consume(c)
        checks[ident+'_typed']=seen and code==c['expected_code']
        err=native[2]
        other=response(cases['key_malformed' if ident=='meta_malformed' else 'meta_malformed'])
        variants={
            'cross_kind':other,'wrong_exit':(2,b'',err),'stdout':(1,b'noise',err),
            'trailing':(1,b'',err+b'warning\n'),'prefix':(1,b'',b'warning\n'+err),
            'missing_lf':(1,b'',err[:-1]),'cr':(1,b'',err.replace(b'\n',b'\r\n')),
            'nul':(1,b'',err+b'\x00'),'operand':(1,b'',err.replace(b'/dev/stdin',b'/tmp/cert')),
            'streams_swapped':(1,err,b''),'signal':(-15,b'',err),
        }
        for label,variant in variants.items():
            _,result=consume(c,variant)
            checks[ident+'_'+label]=result is None
    # Original LibreSSL alternatives stay admitted by the same actual consumers.
    old_cert=(b'unable to load certificate\n123:error:09FFF06C:PEM routines:CRYPTO_internal:no start line:'+
              m.LIBRESSL_PEM_ERROR_PATH+b':Expecting: TRUSTED CERTIFICATE\n')
    old_key=(b'unable to load key\n123:error:09FFF06C:PEM routines:CRYPTO_internal:no start line:'+
             m.LIBRESSL_PEM_ERROR_PATH+b':Expecting: ANY PRIVATE KEY\n')
    checks['legacy_cert']=consume(cases['meta_malformed'],(1,b'',old_cert))[1]=='certificate_malformed'
    checks['legacy_key']=consume(cases['key_malformed'],(1,b'',old_key))[1]=='key_malformed'
    assert len(checks)==26
elif mode=='verify':
    verify=[c for c in f['cases'] if c['family'].startswith('verify_')]
    assert len(verify)==11
    for c in verify:
        native=response(c);seen,code=consume(c)
        checks[c['id']+'_typed']=seen and code=='chain_failed'
        err=native[2]
        variants={
            'code':re.sub(rb'error [0-9]+ at',b'error 99 at',err,count=1),
            'depth':re.sub(rb'at [0-9]+ depth',b'at 2 depth',err,count=1),
            'reason':re.sub(rb'depth lookup: [^\n]+',b'depth lookup: other reason',err,count=1),
            'subject':re.sub(rb'^CN = [^\n]+',b'CN = bad subject',err,count=1),
            'prefix':b'warning\n'+err,'suffix':err+b'warning\n',
            'missing_lf':err[:-1],'cr':err.replace(b'\n',b'\r\n'),
            'nul':err+b'\x00','operand':err.replace(b'/dev/stdin',b'/tmp/cert'),
            'repeated':err+err,'partial':err[:len(err)//2],
            'cross_product':re.sub(rb'error [0-9]+ at [0-9]+ depth lookup: [^\n]+',b'error 20 at 0 depth lookup: certificate has expired',err,count=1),
        }
        for label,bad in variants.items():
            if bad==err: raise AssertionError(label+' mutation was ineffective')
            _,result=consume(c,(2,b'',bad))
            checks[c['id']+'_'+label]=result is None
        for label,bad_tuple in {'exit':(1,b'',err),'stream':(2,err,b'')}.items():
            _,result=consume(c,bad_tuple)
            checks[c['id']+'_'+label]=result is None
    for ident,purpose,host in (('verify_client_purpose_mismatch','sslserver','server.artifact-registry.internal'),
                               ('verify_egs_wrong_hostname','sslclient',''),
                               ('verify_egs_wrong_hostname','sslserver','')):
        _,code=consume(cases[ident],purpose_override=purpose,hostname_override=host)
        checks[ident+'_context_'+purpose+'_'+str(bool(host))]=code is None
    sample=cases['verify_client_wrong_anchor']
    _,code=consume(sample,(0,b'/dev/stdin: OK\n',b''))
    checks['success_control']=code=='pass'
    compact20=(b'CN=fixture.internal\nerror 20 at 0 depth lookup: unable to get local issuer certificate\nerror /dev/stdin: verification failed\n')
    compact62=(b'CN=fixture.internal\nerror 62 at 0 depth lookup: hostname mismatch\nerror /dev/stdin: verification failed\n')
    checks['compact_20']=consume(sample,(2,b'',compact20))[1]=='chain_failed'
    checks['compact_62']=consume(cases['verify_egs_wrong_hostname'],(2,b'',compact62))[1]=='chain_failed'
    lib20=(b'CN = fixture.internal\nerror 20 at 0 depth lookup:unable to get local issuer certificate\n/dev/stdin: verification failed: 20 (unable to get local issuer certificate)\n')
    lib9=(b'CN = fixture.internal\nerror 9 at 0 depth lookup:certificate is not yet valid\n/dev/stdin: verification failed: 9 (certificate is not yet valid)\n')
    lib10=((b'CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup:certificate has expired\n'*3)+b'CN = fixture.internal\nerror 10 at 0 depth lookup:certificate has expired\n/dev/stdin: verification failed: 10 (certificate has expired)\n')
    for name,old in [('20',lib20),('9',lib9),('10',lib10)]:
        checks['libressl_'+name]=consume(sample,(2,old,b''))[1]=='chain_failed'
    assert len(checks)==11*16+3+1+2+3
elif mode=='replay':
    for c in f['cases']:
        seen,code=consume(c)
        checks[c['id']]=seen and code==c['expected_code']
    # These exact native tuples are unreachable failures at later call sites.
    metadata=(b'subject=CN=fixture.internal\nissuer=CN=fixture.internal\n'
              b'notBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Dec 31 23:59:59 2026 GMT\n'
              b'sha256 Fingerprint='+b':'.join([b'AA']*32)+b'\n')
    public=b'-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n'
    der=b'\x30\x81\x80'+b'\x00'*128
    assert m._valid_der_sequence(der)
    argv_meta=(m.OPENSSL,'x509','-in','/dev/stdin','-noout','-subject','-issuer','-dates','-fingerprint','-sha256','-nameopt','RFC2253')
    argv_pem=(m.OPENSSL,'x509','-in','/dev/stdin','-pubkey','-noout')
    argv_der=(m.OPENSSL,'pkey','-pubin','-outform','DER')
    argv_text=(m.OPENSSL,'x509','-in','/dev/stdin','-noout','-text')
    for ident,steps in (
        ('pem_malformed',[(argv_meta,(0,metadata,b'')),(argv_pem,response(controls['pem_malformed']))]),
        ('der_malformed',[(argv_meta,(0,metadata,b'')),(argv_pem,(0,public,b'')),(argv_der,response(controls['der_malformed']))]),
        ('text_malformed',[(argv_meta,(0,metadata,b'')),(argv_pem,(0,public,b'')),(argv_der,(0,der,b'')),(argv_text,response(controls['text_malformed']))]),
    ):
        assert tuple(controls[ident]['argv'])==steps[-1][0]
        pending=list(steps);old_run=m.run_fixed;old_open=m.open_fixed_regular
        def fixed(argv,input_bytes=None,anchor_bytes=None):
            expected,value=pending.pop(0)
            assert tuple(argv)==expected and anchor_bytes is None
            return value
        m.run_fixed=fixed;m.open_fixed_regular=lambda path,limit,read_content=True: b'not a certificate\n'
        try:
            try:
                if ident=='text_malformed': m.cert_role(('fixture','synthetic','client',None,'client'))
                else: m.cert_metadata('synthetic')
                refused=False
            except m.Incomplete: refused=True
            checks[ident+'_remains_incomplete']=refused and not pending
        finally:
            m.run_fixed=old_run;m.open_fixed_regular=old_open
    checks['fixture_identity']=len(cases)==13 and len(inputs)==14 and len(controls)==3
    assert len(checks)==17
else: raise AssertionError('unknown mode')
print(json.dumps(checks,sort_keys=True))
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath(), target3013FixturePath(), mode)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("target 3.0.13 %s probe timed out: %v", mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf("target 3.0.13 %s probe: %v\n%s", mode, err, output)
	}
	var checks map[string]bool
	if err := json.Unmarshal(output, &checks); err != nil {
		t.Fatalf("target 3.0.13 %s JSON: %v\n%s", mode, err, output)
	}
	for label, ok := range checks {
		if !ok {
			t.Errorf("target 3.0.13 %s check failed: %s", mode, label)
		}
	}
	return checks
}

func TestRemoteAlphaESServiceTLSStatusTarget3013MalformedResponses(t *testing.T) {
	if got := len(runTarget3013Probe(t, "malformed")); got != 26 {
		t.Fatalf("malformed roster = %d, want 26", got)
	}
}

func TestRemoteAlphaESServiceTLSStatusTarget3013VerifyFailureResponses(t *testing.T) {
	if got := len(runTarget3013Probe(t, "verify")); got != 185 {
		t.Fatalf("verify roster = %d, want 185", got)
	}
}

func TestRemoteAlphaESServiceTLSStatusTarget3013NativeReplay(t *testing.T) {
	if got := len(runTarget3013Probe(t, "replay")); got != 17 {
		t.Fatalf("native replay roster = %d, want 17", got)
	}
}

// This contained fixture keeps collect, verify_chain, validate_document, and
// main's publication gate real. Only fixed material lookup, unrelated child
// responses, target tuple injection, and the local publication sink are fake.
func runTarget3013PublicationProbe(t *testing.T, scope string, baseline map[string]any, fixtureRoot string) (map[string]bool, map[string]any) {
	t.Helper()
	work := t.TempDir()
	baselinePath := filepath.Join(work, "baseline.json")
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	const probe = `
import base64,copy,datetime as dt,hashlib,importlib.util,json,os,pathlib,stat,sys
source,fixture_path,baseline_path,scope,fixture_root,work=sys.argv[1:]
spec=importlib.util.spec_from_file_location('target3013_publication',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=json.load(open(fixture_path,'r',encoding='utf-8'))
baseline=json.load(open(baseline_path,'r',encoding='utf-8'))
root=pathlib.Path(fixture_root).resolve()
fixed={'/etc/execution-substrate/ars-tls':str(root/'etc/execution-substrate/ars-tls'),
       '/etc/execution-substrate/egs-tls':str(root/'etc/execution-substrate/egs-tls'),
       '/etc/execution-substrate/es-tls':str(root/'etc/execution-substrate/es-tls'),
       '/etc/execution-substrate/tls':str(root/'etc/execution-substrate/tls'),
       '/etc/execution-substrate/':str(root/'etc/execution-substrate')+'/'}
def relocate(value):
    if isinstance(value,str):
        for old,new in fixed.items():
            if value.startswith(old): return new+value[len(old):]
        return value
    if isinstance(value,tuple): return tuple(relocate(x) for x in value)
    if isinstance(value,dict): return {k:relocate(v) for k,v in value.items()}
    return value
m.SCOPES=relocate(m.SCOPES)
case_id='verify_client_wrong_anchor' if scope=='artifact-registry' else 'verify_egs_wrong_anchor'
case=next(c for c in f['cases'] if c['id']==case_id)
input_bytes=base64.b64decode(f['inputs'][case['input_role']]['bytes_b64'],validate=True)
anchor_bytes=base64.b64decode(f['inputs'][case['anchor_role']]['bytes_b64'],validate=True)
response=(case['exit'],base64.b64decode(case['stdout_b64'],validate=True),base64.b64decode(case['stderr_b64'],validate=True))
assert hashlib.sha256(input_bytes).hexdigest()==case['input_sha256']
assert hashlib.sha256(anchor_bytes).hexdigest()==case['anchor_sha256']
target_index=0 if scope=='artifact-registry' else 1
target_spec=m.SCOPES[scope]['verify'][target_index]
assert target_spec[3]==case['argv'][5]
assert (target_spec[4] if target_spec[3]=='sslserver' else '')== (case['argv'][7] if case['family']=='verify_server' else '')
cert_by_label={record['label']:record for record in baseline['certificates']}
pair_by_label={record['label']:record for record in baseline['key_pairs']}
checks={};target_calls=[];all_verify=[];unknown=[False]
def cert_role(item,observed_at):
    record=copy.deepcopy(cert_by_label[item[0]])
    raw=b'synthetic-public-fixture'
    if item[0]==target_spec[1]:
        raw=anchor_bytes;record['sha256']=case['anchor_sha256']
    if item[0]==target_spec[2]:
        raw=input_bytes;record['sha256']=case['input_sha256']
        record['not_before']=(observed_at-dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        record['not_after']=(observed_at-dt.timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        record['expired']=True;record['not_yet_valid']=False
        record['status']='fail';record['code']='certificate_expired'
    return record,raw
m.collect_topology=lambda _scope: copy.deepcopy(baseline['topology'])
m.cert_role=cert_role
m.key_pair=lambda label,_cert,_path: copy.deepcopy(pair_by_label[label])
def fixed_run(argv,input_bytes=None,anchor_bytes=None):
    assert argv[1]=='verify'
    all_verify.append(tuple(argv))
    if len(all_verify)-1==target_index:
        assert tuple(argv)==tuple(case['argv'])
        target_calls.append((input_bytes,anchor_bytes))
        assert input_bytes==globals()['input_bytes'] and anchor_bytes==globals()['anchor_bytes']
        return (2,b'',response[2]+b'warning\n') if unknown[0] else response
    return 0,b'/dev/stdin: OK\n',b''
m.run_fixed=fixed_run
prior='a'*32
record=m.collect(scope,prior)
m.validate_document(record,scope,prior)
status_by_label={x['label']:x for x in record['verification']}
cert_status={x['label']:x for x in record['certificates']}
checks['whole_collection_chain_failure']=status_by_label[target_spec[0]]['code']=='chain_failed'
checks['expiry_does_not_skip_chain']=cert_status[target_spec[2]]['code']=='certificate_expired' and len(target_calls)==1
checks['verification_order']=all_verify==[tuple(([m.OPENSSL,'verify','-trusted',m.TRUST_FD_OPERAND,'-purpose',v[3]]+(['-verify_hostname',v[4]] if v[4] else [])+['/dev/stdin'])) for v in m.SCOPES[scope]['verify']]
checks['completed_fail_document']=record['result']=={'status':'fail','ok':False} and 'chain_failed' in record['blockers'] and 'certificate_expired' in record['blockers']
checks['encoded_without_raw_stream']=response[2] not in m.encode_document(record,scope)
canonical=pathlib.Path(work)/'previous.json';previous=b'previous generation unchanged\n';canonical.write_bytes(previous)
lock=pathlib.Path(work)/'fixture.lock'
m.open_status_dir=lambda:os.open(work,os.O_RDONLY|os.O_DIRECTORY)
m.open_scope_lock=lambda _fd,_name:os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
m.validate_process_capability=lambda:None
m.preexisting_generation=lambda _fd,_scope:m._PriorSummarySnapshot(m._PriorSummaryState.VALID,prior)
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
m.LATCHED_SIGNAL=None
published=[]
def sink(_fd,_scope,payload):
    published.append(payload);canonical.write_bytes(payload)
m.publish=sink
known_exit=m.main(['--scope',scope])
checks['known_reaches_publication']=known_exit==1 and len(published)==1 and canonical.read_bytes()==published[0] and previous!=published[0]
unknown[0]=True;canonical.write_bytes(previous);published.clear();target_calls.clear();all_verify.clear()
unknown_exit=m.main(['--scope',scope])
checks['unknown_preserves_previous']=unknown_exit==1 and canonical.read_bytes()==previous and published==[]
checks['unknown_still_checks_target']=len(target_calls)==1 and len(all_verify)>=target_index+1
checks['prior_generation_replaced']=record['generation']!=prior
print(json.dumps({'checks':checks,'document':record},sort_keys=True))
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), target3013FixturePath(), baselinePath, scope, fixtureRoot, work)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("target 3.0.13 publication %s timed out: %v", scope, ctx.Err())
	}
	if err != nil {
		t.Fatalf("target 3.0.13 publication %s: %v\n%s", scope, err, output)
	}
	var result struct {
		Checks   map[string]bool `json:"checks"`
		Document map[string]any  `json:"document"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("target 3.0.13 publication JSON: %v\n%s", err, output)
	}
	for label, ok := range result.Checks {
		if !ok {
			t.Errorf("target 3.0.13 publication %s failed: %s", scope, label)
		}
	}
	return result.Checks, result.Document
}

func TestRemoteAlphaESServiceTLSStatusTarget3013FailurePublicationSemantics(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			var fixture *remoteAlphaESServiceTLSFixture
			if scope == "artifact-registry" {
				fixture = setupRemoteAlphaESServiceTLSFixture(t, false)
			} else {
				fixture = setupRemoteAlphaESGovernanceTLSFixture(t, false)
			}
			baseline := runRemoteAlphaESTLSFixture(t, fixture, scope)
			checks, document := runTarget3013PublicationProbe(t, scope, baseline, fixture.root)
			if len(checks) != 9 {
				t.Fatalf("publication roster = %d, want 9", len(checks))
			}
			if err := validateRemoteAlphaESTLSStatusDocument(t, document, scope, strings.Repeat("a", 32), fixture.root); err != nil {
				t.Fatalf("unchanged status reader rejected completed failure: %v", err)
			}
		})
	}
}
