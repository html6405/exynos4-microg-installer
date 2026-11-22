#!/usr/bin/env python3
"""Prepare an UNFLASHABLE reviewed payload; never invokes adb/mount/root."""
import pathlib,hashlib,json,zipfile,shutil,struct,xml.etree.ElementTree as E,subprocess
p=pathlib.Path(__file__).resolve().parent;d=p/'privileged-payload';d.mkdir(exist_ok=True);s=d/'system';files={}
def sha(b):return hashlib.sha256(b).hexdigest()
def put(rel,b,mode='0644'):
 f=s/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b);files[rel]={'logical_path':rel,'sha256':sha(b),'size':len(b),'uid':0,'gid':0,'mode':mode,'selinux_context':'u:object_r:system_file:s0'}
components=[]
for name,pkg,where,h,code in [('com.google.android.gms-252432036.apk','com.google.android.gms','product/priv-app/Exynos4MicroGServices/Services.apk','1094fa60ace2367ac52bd08d1bd4f33fa8144ba930e355121b28234b8ebbf382',252432036),('com.android.vending-84022636.apk','com.android.vending','product/priv-app/Exynos4MicroGCompanion/Companion.apk','3f1bde2f72bca746fbb53b61a32c2a85fcb026f886ee96d6fe9a05de9a6c6d5b',84022636)]:
 b=(p/'inputs'/name).read_bytes();assert sha(b)==h;put(where,b);components.append({'package':pkg,'version_code':code,'version_name':'0.3.18.252432' if code==252432036 else '0.3.18.40226','signer_sha256':'9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165','apk_sha256':h,'source_url':'https://github.com/microg/GmsCore/releases/download/v0.3.18.252432/'+name,'source_revision':'v0.3.18.252432'})
 if pkg=='com.google.android.gms':
  with zipfile.ZipFile(p/'inputs'/name) as z:
   for n in z.namelist():
    if n.startswith('lib/armeabi-v7a/') and n.endswith('.so'):
     b=z.read(n);assert b[:5]==b'\x7fELF\x01' and struct.unpack_from('<H',b,18)[0]==40
     put('product/priv-app/Exynos4MicroGServices/lib/arm/'+pathlib.PurePosixPath(n).name,b)
# Generate only requested/platform-defined privileged permissions. No runtime grant XML.
ns='{http://schemas.android.com/apk/res/android}';platform=E.parse(p.parents[1]/'frameworks/base/core/res/AndroidManifest.xml').getroot();sdk='/home/html6405/Android/Sdk/build-tools/35.0.0/aapt'
import re
for pkg,name,outname in [('com.google.android.gms','com.google.android.gms-252432036.apk','microg-services'),('com.android.vending','com.android.vending-84022636.apk','microg-companion')]:
 text=subprocess.check_output([sdk,'dump','permissions',str(p/'inputs'/name)],text=True);requested=set(re.findall(r"uses-permission: name='([^']+)'",text));root=E.Element('permissions');block=E.SubElement(root,'privapp-permissions',{'package':pkg})
 for permission in platform.findall('permission'):
  n=permission.get(ns+'name');pl=permission.get(ns+'protectionLevel','normal')
  if n in requested and 'privileged' in pl:E.SubElement(block,'permission',{'name':n})
 E.indent(root);put('product/etc/permissions/privapp-permissions-exynos4-'+outname+'.xml',E.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n')
# Explicit minimal push background exemptions, not account/registration opt-ins.
put('product/etc/sysconfig/exynos4-microg.xml',b'<?xml version="1.0" encoding="utf-8"?>\n<config>\n  <allow-in-power-save package="com.google.android.gms" />\n  <allow-in-data-usage-save package="com.google.android.gms" />\n</config>\n')
marker='etc/exynos4-google-services/installed.json';script='addon.d/50-exynos4-google-services.sh';owned=sorted([*files,marker])
body='''#!/sbin/sh
# ADDOND_VERSION=3
# TEST CANDIDATE: requires reviewed SAR/backuptool repair and two real Vanilla OTAs.
. /tmp/backuptool.functions
list_files() {
cat <<'EXYNOS4_FILES'
'''+ '\n'.join(owned)+'''
EXYNOS4_FILES
}
case "$1" in
 backup) list_files | while IFS= read -r f; do backup_file "$S/$f"; done ;;
 restore) list_files | while IFS= read -r f; do restore_file "$S/$f"; done ;;
 pre-backup|post-backup|pre-restore|post-restore) : ;;
 *) exit 1 ;;
esac
'''
put(script,body.encode(),'0755')
m={'schema':1,'flavor':'microg-companion','os_sdk':36,'abi':'armeabi-v7a','rom_support_contract':'HTML6405 LOS23.2 restricted microG spoofing; actual self-check required','components':components,'files':[files[k] for k in sorted(files)],'manifest_self':{'logical_path':marker,'hash_source':'external artifact audit; excluded from own files to avoid recursive hash'},'preservation_owner':script,'ota_validation':{'status':'UNVERIFIED','required_cycles':2,'common_backuptool_fix_required':True},'candidate_not_flashable':True}
f=s/marker;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(json.dumps(m,indent=2)+'\n')
audit=[*m['files'],{'logical_path':marker,'sha256':sha(f.read_bytes()),'size':f.stat().st_size,'uid':0,'gid':0,'mode':'0644','selinux_context':'u:object_r:system_file:s0'}];(d/'payload-audit.json').write_text(json.dumps(audit,indent=2)+'\n');(d/'NOT-FLASHABLE.txt').write_text('Payload only. No update-binary, mount/writer or userdata migration. Root review and common OTA repair required before any recovery installer. Native libs/privilege/system startup UNTESTED.\n')
art=p/'artifacts/exynos4-los23-microg-privileged-0.3.18.252432-UNFLASHABLE-PAYLOAD.zip';assert not art.exists(),'Frozen output exists'
with zipfile.ZipFile(art,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for f in sorted(d.rglob('*')):
  if f.is_file():z.write(f,str(f.relative_to(d)))
with zipfile.ZipFile(art) as z:assert z.testzip() is None
h=sha(art.read_bytes());art.with_suffix('.zip.sha256').write_text(h+'  '+art.name+'\n');print(json.dumps({'artifact':str(art),'zip_size':art.stat().st_size,'raw_payload_bytes':sum(x['size'] for x in audit),'sha256':h,'files':len(audit),'flashable':False,'device_action':'NONE'},indent=2))
