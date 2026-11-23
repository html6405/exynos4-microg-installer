#!/usr/bin/env python3
"""Build unsigned Recovery TEST ZIPs from frozen, audited payloads; no ADB."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,zipfile,tempfile,subprocess,re,stat,shutil,struct
P=Path(__file__).resolve().parent
INPUTS={'microg-phonesky': (P/'microg-phonesky-r7.payload.zip', '309a1105598c5490c1756b26fb49266fbaa09079c34e615dbde558f0ff6e7b69')}
AAPT=Path('/home/html6405/Android/Sdk/build-tools/37.0.0/aapt');SIGNER=AAPT.parent/'lib/apksigner.jar'
MARKER='etc/exynos4-google-services/installed.json';ADDON='addon.d/50-exynos4-google-services.sh'
def hfile(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def path_ok(rel):
 assert rel and not rel.startswith('/') and '..' not in rel and '//' not in rel and re.fullmatch(r'[A-Za-z0-9._/+-]+',rel),rel
 assert rel in [MARKER,ADDON] or rel.startswith(('product/app/','product/priv-app/','product/overlay/','product/etc/','product/lib/','system_ext/app/','system_ext/priv-app/','system_ext/etc/')) or rel=='product/framework/com.google.android.dialer.support.jar',rel
 assert rel.endswith(('.apk','.xml','.json','.so','.jar','.der','.rc')) or rel==ADDON,rel
 return rel

def info(name,mode=0o644):
 i=zipfile.ZipInfo(name,(2026,11,22,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3;i.external_attr=(stat.S_IFREG|mode)<<16;return i

def command(args):
 r=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=45)
 assert r.returncode==0,(args[0],r.stdout,r.stderr)
 return r.stdout

ap=argparse.ArgumentParser();ap.add_argument('--flavor',choices=list(INPUTS),required=True);a=ap.parse_args()
source,expected=INPUTS[a.flavor];assert hfile(source)==expected
tool=P/'mtg-arm-toybox';assert tool.stat().st_size==1188740 and hfile(tool)=='3dfaacc17df061913f47258a1aadcf1a42167f814de73de57c737b650340ecca'
abx_helper=(P/'package-state-abx.awk').read_text().rstrip();abx_sha=hashlib.sha256(abx_helper.encode()).hexdigest()
raw_template=(P/'recovery-writer.sh.in').read_text();assert raw_template.rstrip().endswith('writer_main "$@"')
builds=P/'recovery-test-builds';builds.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='package-',dir=str(builds)) as temp:
 stage=Path(temp)/'system';stage.mkdir()
 with zipfile.ZipFile(source) as zin:
  assert zin.testzip() is None
  names=zin.namelist();assert len(names)==len(set(names)),'duplicate archive member'
  for i in zin.infolist():
   assert not i.filename.startswith('/') and '..' not in PurePosixPath(i.filename).parts and '\\' not in i.filename,i.filename
   assert stat.S_IFMT(i.external_attr>>16) in [0,stat.S_IFREG,stat.S_IFDIR],i.filename
   assert not (i.flag_bits&1),'encrypted source ZIP'
   if i.is_dir():continue
   if not i.filename.startswith('system/'):
    assert i.filename in ['UNTESTED-NOT-FLASHABLE.txt','NOT-FLASHABLE.txt','payload-audit.json'],i.filename
    continue
   rel=path_ok(i.filename.removeprefix('system/'));dest=stage/rel;dest.parent.mkdir(parents=True,exist_ok=True)
   with zin.open(i) as r,dest.open('wb') as w:shutil.copyfileobj(r,w,1048576)
 manifest=json.loads((stage/MARKER).read_text());assert manifest['flavor']==a.flavor and manifest['schema']==1
 if a.flavor=='minimal-gapps':assert manifest['profile']=='compat','experimental profile not enabled for Recovery writer'
 declared={r['logical_path']:r for r in manifest['files']}
 actual={f.relative_to(stage).as_posix():f for f in stage.rglob('*') if f.is_file()}
 assert set(actual)==set(declared)|{MARKER,ADDON},'manifest/payload file-set mismatch'
 for rel,r in declared.items():assert hfile(actual[rel])==r['sha256'] and actual[rel].stat().st_size==r['size'],rel
 components={r['package']:r for r in manifest['components']};assert len(components)==len(manifest['components'])
 signatures=[];apk_ids=set()
 for rel,f in actual.items():
  if rel.endswith('.so'):
   b=f.read_bytes()[:20];assert b[:4]==b'\x7fELF' and b[4]==1 and struct.unpack_from('<H',b,18)[0]==40,rel
  if not rel.endswith('.apk'):continue
  bad=command([AAPT,'dump','badging',f]);fields=dict(re.findall(r"(\w+)='([^']*)'",bad.splitlines()[0]));pkg=fields['name'];assert pkg in components and pkg not in apk_ids;apk_ids.add(pkg);c=components[pkg]
  assert int(fields['versionCode'])==c['version_code'] and hfile(f)==c['apk_sha256'],pkg
  sig=command(['java','-Xmx128m','-jar',SIGNER,'verify','--print-certs','--min-sdk-version','36',f])
  certs={v for k,v in re.findall(r'^(.+?) certificate SHA-256 digest: ([0-9a-f]+)',sig,re.M) if k.rstrip(':')!='Source Stamp Signer'}
  wanted=c['signer_sha256'];wanted={wanted} if isinstance(wanted,str) else set(wanted)
  if a.flavor=='minimal-gapps' and not wanted:
   # Older inventory regex omitted SDK-ranged v3 signer lines. Re-audit stored
   # official APK signature output; never infer trust from the incoming APK alone.
   auditlog=P/'apk-audit'/(Path(rel).stem+'.signature.txt')
   if not auditlog.exists():auditlog=P/'apk-audit'/('system__'+rel.replace('/','__').removesuffix('.apk')+'.signature.txt')
   prior=auditlog.read_text()
   wanted={v for k,v in re.findall(r'^(.+?) certificate SHA-256 digest: ([0-9a-f]+)',prior,re.M) if k.rstrip(':')!='Source Stamp Signer'}
   c['signer_sha256']=sorted(wanted)
   c['certificate_sha256']=sorted(wanted)
  assert certs and certs==wanted,pkg
  with zipfile.ZipFile(f) as az:
   libs=[x for x in az.namelist() if x.startswith('lib/') and x.endswith('.so')]
   if libs:
    arm=[x for x in libs if x.startswith('lib/armeabi-v7a/')];assert arm,pkg
    for n in arm:
     b=az.read(n)[:20];assert b[:4]==b'\x7fELF' and b[4]==1 and struct.unpack_from('<H',b,18)[0]==40,(pkg,n)
  signatures.append({'package':pkg,'version_code':c['version_code'],'apk_sha256':hfile(f),'signer_sha256':sorted(certs),'verified_at_api':36})
 assert apk_ids==set(components)
 needed={'com.google.android.gms','com.android.vending'}
 if a.flavor=='minimal-gapps':needed.add('com.google.android.gsf')
 assert needed<=apk_ids
 if a.flavor=='microg-phonesky':assert apk_ids==needed
 if a.flavor=='microg-companion':
  assert apk_ids==needed
  assert components['com.google.android.gms']['signer_sha256']==components['com.android.vending']['signer_sha256']=='9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165'
 elif a.flavor=='minimal-gapps':
  import xml.etree.ElementTree as ET
  perms=command([AAPT,'dump','permissions',actual['product/priv-app/GmsCore/GmsCore.apk']])
  five={'GET_ROLE_HOLDERS','OBSERVE_ROLE_HOLDERS','LOG_COMPAT_CHANGE','READ_COMPAT_CHANGE_CONFIG','MANAGE_SECURE_LOCK_DEVICE'}
  req={m for m in re.findall(r"uses-permission: name='android.permission.([^']+)'",perms)}
  xml=ET.parse(stage/'product/etc/permissions/privapp-permissions-google-product.xml')
  allowed={n.get('name').removeprefix('android.permission.') for b in xml.iter('privapp-permissions') if b.get('package')=='com.google.android.gms' for n in b.findall('permission')}
  assert five<=req and five<=allowed
 # Only generated marker metadata changes; APK/library/config bytes remain audited.
 manifest['candidate_not_flashable']=False
 manifest['flashable']=True
 manifest['status']='UNSIGNED_RECOVERY_TEST_RUNTIME_AND_OTA_UNVERIFIED'
 manifest['test_installer']={'version':1,'source_payload_sha256':expected,'writer_template_sha256':hashlib.sha256(raw_template.encode()).hexdigest(),'abx_guard_sha256':abx_sha,'clean_install_only':True,'public_release_approved':False}
 manifest['ota_validation']['status']='UNVERIFIED';manifest['ota_validation']['completed_cycles']=0
 (stage/MARKER).write_text(json.dumps(manifest,indent=2)+'\n')
 actual={f.relative_to(stage).as_posix():f for f in stage.rglob('*') if f.is_file()}
 table=[];records=[]
 for rel,f in sorted(actual.items()):
  path_ok(rel);r=declared.get(rel,{})
  assert r.get('uid',0)==0 and r.get('gid',0)==0 and r.get('selinux_context','u:object_r:system_file:s0')=='u:object_r:system_file:s0'
  mode='0755' if rel==ADDON else '0644';assert str(r.get('mode',mode))==mode
  digest=hfile(f);size=f.stat().st_size
  table.append('|'.join([digest,str(size),'0','0',mode,'u:object_r:system_file:s0',rel]));records.append({'logical_path':rel,'sha256':digest,'size':size,'uid':0,'gid':0,'mode':mode,'selinux_context':'u:object_r:system_file:s0'})
 rendered=raw_template.replace('@@ABX_HELPER@@',abx_helper).replace('@@FLAVOR@@',a.flavor).replace('@@FILE_COUNT@@',str(len(table))).replace('@@PAYLOAD_BYTES@@',str(sum(r['size'] for r in records))).replace('@@INPUT_SHA@@',expected).replace('@@FILES@@','\n'.join(table));assert '@@' not in rendered
 script=builds/(a.flavor+'-update-binary.sh');script.write_text(rendered);command(['sh','-n',script])
 output=builds/('Exynos4-LOS23-'+a.flavor+'-TWRP-r7-TEST-UNSIGNED.zip');temporary=output.with_suffix('.zip.partial')
 report={'flavor':a.flavor,'status':'PREPARED_UNSIGNED_TEST_NOT_DEVICE_OR_OTA_VERIFIED','source_payload_sha256':expected,'writer_template_sha256':hashlib.sha256(raw_template.encode()).hexdigest(),'abx_guard_sha256':abx_sha,'update_binary_sha256':hashlib.sha256(rendered.encode()).hexdigest(),'file_count':len(records),'system_bytes':sum(r['size'] for r in records),'files':records,'apk_signature_checks':signatures,'production_release_approved':False,'power_loss_atomic':False,'durable_rollback_requires_recovery_operator':True}
 with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as zout:
  zout.writestr(info('tools/toybox',0o700),tool.read_bytes())
  zout.writestr(info('META-INF/com/google/android/update-binary',0o755),rendered)
  zout.writestr(info('META-INF/com/google/android/updater-script'),'# Exynos4 UNSIGNED TEST installer; uses update-binary\n')
  for rel,f in sorted(actual.items()):
   with f.open('rb') as r,zout.open(info('system/'+rel,0o755 if rel==ADDON else 0o644),'w') as w:shutil.copyfileobj(r,w,1048576)
  zout.writestr(info('tools/build-report.json'),json.dumps(report,indent=2)+'\n')
  zout.writestr(info('README-TEST.txt'),'UNSIGNED TEST ZIP, not a production release. Clean ecosystem and userdata required. No accounts/app data are removed. A durable system-file rollback helper is retained in /data/local/tmp/exynos4-google-services-recovery. Power loss is not atomic: return to recovery and use the helper. Two real Vanilla OTA cycles remain unverified.\n')
 with zipfile.ZipFile(temporary) as check:
  assert check.testzip() is None
  for r in records:assert hashlib.sha256(check.read('system/'+r['logical_path'])).hexdigest()==r['sha256']
 temporary.replace(output)
 report.update({'zip':output.name,'zip_size':output.stat().st_size,'zip_sha256':hfile(output),'crc_pass':True})
 (builds/(a.flavor+'-build-report.json')).write_text(json.dumps(report,indent=2)+'\n')
 (builds/(output.name+'.sha256sum')).write_text(report['zip_sha256']+'  '+output.name+'\n')
 print(json.dumps({k:report[k] for k in ['flavor','zip','zip_size','zip_sha256','file_count','system_bytes','crc_pass','status']},indent=2))
