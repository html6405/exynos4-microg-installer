#!/usr/bin/env python3
"""Full main-flow fixtures: real temp files, mocked block/mount/ownership/labels.
No real mounts, root devices, chown or SELinux label operations are performed.
"""
from pathlib import Path
import tempfile,subprocess,hashlib,zipfile,json,shlex,os,stat
P=Path(__file__).parent
TEMPLATE=(P/'recovery-writer.sh.in').read_text()
PAYLOAD={
 'addon.d/50-exynos4-google-services.sh':b'#!/sbin/sh\n# fixture addon\n',
 'etc/exynos4-google-services/installed.json':b'{"schema":1,"flavor":"minimal-gapps"}\n',
 'product/etc/permissions/test.xml':b'NEW_CONFIG\n',
 'product/priv-app/TestPackage/Test.apk':b'FIXTURE_NOT_AN_ANDROID_APK\n',
 'product/priv-app/TestPackage/lib/arm/libc++_shared.so':b'FIXTURE_NOT_REAL_ELF\n',
}
CASES=['success','manual_rollback','bad_hash','duplicate_archive_entry','symlink_destination','copy_failure','chcon_failure','signal_failure','backup_corruption','foreign_change','unfinished_transaction','microg_xml','google_abx','system_microg','unknown_package_state','missing_package_state_with_apps','unknown_model','wrong_rom_model','wrong_api','wrong_abi','locked_data','unknown_crypto','wrong_data_mount','low_system_space','low_tmp_space','hardlink_original','bad_table_path','duplicate_table','preexisting_workspace','wrong_system_block','wrong_system_size','dynamic_layout','ab_layout','existing_marker','existing_addon','symlink_package_state','power_loss','retained_ce_data','retained_de_data','retained_legacy_data','retained_login_data','fallback_plain','fallback_f2fs','fallback_overlay','fallback_fscrypt','fallback_missing_state','fallback_encoded_user','directory_context_mismatch']
STUBS=r'''
getprop() {
 case "$1" in
  ro.product.model) [ "$CASE" != unknown_model ] && echo GT-N8010 || echo GT-N8020 ;;
  ro.boot.slot_suffix) [ "$CASE" != ab_layout ] || echo _a ;;
  ro.boot.dynamic_partitions) [ "$CASE" != dynamic_layout ] && echo false || echo true ;;
  ro.crypto.state) case "$CASE" in locked_data) echo encrypted ;; unknown_crypto|fallback_*) : ;; *) echo unencrypted ;; esac ;;
 esac
}
uname() { [ "$CASE" = unknown_crypto ] && echo 6.1.0 || echo 3.0.101-TWRP-fixture; }
id() { [ "${1:-}" = -u ] && echo 0 || command id "$@"; }
readlink() {
 for last do :; done
 case "$last" in
  */by-name/SYSTEM|/dev/block/mmcblk0p9) [ "$CASE" != wrong_system_block ] && echo /dev/block/mmcblk0p9 || echo /dev/block/mmcblk0p8 ;;
  */by-name/USERDATA|/dev/block/mmcblk0p12) echo /dev/block/mmcblk0p12 ;;
  *) command readlink "$@" ;;
 esac
}
block_device() { case "$1" in /dev/block/mmcblk0p9|/dev/block/mmcblk0p12) return 0 ;; *) return 1 ;; esac; }
blockdev() { [ "$1" = --getsize64 ] && [ "$2" = /dev/block/mmcblk0p9 ] || return 1; [ "$CASE" != wrong_system_size ] && echo 2147483648 || echo 1073741824; }
stat() {
 if [ "${1:-}" = -c ]; then
  case "$2" in %u|%g) echo 0 ;; *) command stat "$@" ;; esac
 else command stat "$@"; fi
}
chown() { printf 'chown %s\n' "$*" >> "$ROOT/calls"; return 0; }
chcon() {
 printf 'chcon %s\n' "$*" >> "$ROOT/calls"
 case "$CASE:$2" in chcon_failure:*Test.apk.exynos4-*.tmp)
  if [ ! -e "$ROOT/injected" ]; then : > "$ROOT/injected"; return 1; fi ;;
 esac
 return 0
}
ls() { if [ "${1:-}" = -Zd ]; then
 if [ "$CASE" = directory_context_mismatch ] && [ "$2" = "$S/etc/exynos4-google-services" ]; then printf 'u:object_r:unlabeled:s0 %s\n' "$2"; return 0; fi
 printf 'u:object_r:system_file:s0 %s\n' "$2"; else command ls "$@"; fi; }
sync() { return 0; }
df() {
 for last do :; done
 free=999999999
 [ "$CASE:$last" != "low_system_space:$S" ] || free=1
 [ "$CASE:$last" != "low_tmp_space:$TMPROOT" ] || free=1
 printf 'Filesystem 1024-blocks Used Available Capacity Mounted_on\nfixture 999999999 0 %s 0%% fixture\n' "$free"
}
mount() {
 case "$1" in
  -t)
   [ "$2" = ext4 ] && [ "$3" = -o ] && [ "$4" = ro ] && [ "$5" = /dev/block/mmcblk0p9 ] && [ "$6" = "$MNT" ] || return 1
   command mv "$ROOT/source/system" "$MNT/system" || return 1
   printf '/dev/block/mmcblk0p9 %s ext4 ro 0 0\n' "$MNT" >> "$MOUNTS"
   ;;
  -o)
   [ "$3" = "$MNT" ] || return 1
   case "$2" in remount,rw) option=rw ;; remount,ro) option=ro ;; *) return 1 ;; esac
   awk -v m="$MNT" -v opt="$option" '{if($2==m)$4=opt;print}' "$MOUNTS" > "$ROOT/mounts.new" && command mv "$ROOT/mounts.new" "$MOUNTS"
   ;;
  *) return 1 ;;
 esac
}
umount() {
 [ "$1" = "$MNT" ] || return 1
 command mv "$MNT/system" "$ROOT/source/system" || return 1
 awk -v m="$MNT" '$2!=m' "$MOUNTS" > "$ROOT/mounts.new" && command mv "$ROOT/mounts.new" "$MOUNTS"
}
cp() {
 for last do :; done
 case "$CASE:$last" in
  copy_failure:*Test.apk.exynos4-*.tmp)
   if [ ! -e "$ROOT/injected" ]; then : > "$ROOT/injected"; return 1; fi ;;
  power_loss:*Test.apk.exynos4-*.tmp)
   if [ ! -e "$ROOT/injected" ]; then : > "$ROOT/injected"; command cp "$@"; kill -KILL $$; return 1; fi ;;
  signal_failure:*Test.apk.exynos4-*.tmp)
   if [ ! -e "$ROOT/injected" ]; then : > "$ROOT/injected"; command cp "$@"; kill -TERM $$; return 1; fi ;;
  foreign_change:*Test.apk.exynos4-*.tmp)
   if [ ! -e "$ROOT/injected" ]; then : > "$ROOT/injected"; printf 'FOREIGN\n' > "$S/product/etc/permissions/test.xml"; return 1; fi ;;
 esac
 command cp "$@" || return 1
 case "$CASE:$last" in backup_corruption:*/original/product/etc/permissions/test.xml) printf 'BAD_BACKUP\n' >> "$last" ;; esac
}
'''
results=[]
for case in CASES:
 with tempfile.TemporaryDirectory(prefix='exynos4-recovery-fixture-') as d:
  root=Path(d);source=root/'source/system';source.mkdir(parents=True);data=root/'data';data.mkdir();(data/'system').mkdir();(data/'media/0/TWRP').mkdir(parents=True);(data/'media/0/TWRP/keep.txt').write_text('PERSONAL_BACKUP\n')
  for sub in ['product/etc/permissions','system_ext','etc','addon.d']:(source/sub).mkdir(parents=True,exist_ok=True)
  (source/'addon.d/50-lineage.sh').write_text('BASELINE_ADDON\n');(source/'etc/keep.txt').write_text('UNRELATED\n')
  old=source/'product/etc/permissions/test.xml';old.write_bytes(b'OLD_CONFIG\n');old.chmod(0o600)
  props='ro.build.version.sdk=36\nro.product.cpu.abi=armeabi-v7a\nro.lineage.version=23.2-20261122-HTML6405-n8010\n'
  if case=='wrong_api':props=props.replace('sdk=36','sdk=35')
  if case=='wrong_abi':props=props.replace('armeabi-v7a','arm64-v8a')
  if case=='wrong_rom_model':props=props.replace('n8010','n8000')
  (source/'product/etc/build.prop').write_text(props)
  (root/'ext4features').mkdir()
  if case.startswith('fallback_'):
   (data/'user/0').mkdir(parents=True);(data/'user_de/0').mkdir(parents=True)
  if case=='fallback_fscrypt':(root/'ext4features/encryption').write_text('supported')
  if case=='fallback_encoded_user':(data/'user/ENCODED').mkdir()
  (data/'system/packages.xml').write_text('<?xml version="1.0"?><packages><package name="example.personal.app"/></packages>')
  if case=='microg_xml':(data/'system/packages.xml').write_text('<?xml version="1.0"?><packages><package name="com.google.android.gms"/></packages>')
  if case=='google_abx':(data/'system/packages.xml').write_bytes(b'ABX\x00\x00com.android.vending\x00')
  if case=='unknown_package_state':(data/'system/packages.xml').write_bytes(b'ENCRYPTED_OR_UNKNOWN')
  if case=='missing_package_state_with_apps':
   (data/'system/packages.xml').unlink();(data/'app/random').mkdir(parents=True);(data/'app/random/base.apk').write_bytes(b'ORPHAN')
  if case in ['retained_ce_data','retained_de_data','retained_legacy_data','retained_login_data']:
   (data/'system/packages.xml').unlink()
   parent={'retained_ce_data':'user/0','retained_de_data':'user_de/10','retained_legacy_data':'data','retained_login_data':'user/0'}[case]
   (data/parent/('com.google.android.gsf.login' if case=='retained_login_data' else 'com.google.android.gms')).mkdir(parents=True)
  if case=='fallback_missing_state':(data/'system/packages.xml').unlink()
  if case=='existing_marker':
   (source/'etc/exynos4-google-services').mkdir();(source/'etc/exynos4-google-services/installed.json').write_text('{}')
  if case=='existing_addon':(source/'addon.d/30-gapps.sh').write_text('OLD_ADDON')
  if case=='symlink_package_state':
   (data/'system/packages.xml').rename(root/'foreign-packages.xml');(data/'system/packages.xml').symlink_to(root/'foreign-packages.xml')
  if case=='system_microg':(source/'product/priv-app/Exynos4MicroGServices').mkdir(parents=True)
  if case=='hardlink_original':os.link(old,root/'original-hardlink')
  if case=='symlink_destination':
   (source/'product/etc/permissions').rename(root/'outside');(source/'product/etc/permissions').symlink_to(root/'outside')
  txroot=data/'local/tmp/exynos4-google-services-recovery'
  if case=='unfinished_transaction':
   t=txroot/'txn-1-1';t.mkdir(parents=True);txroot.chmod(0o700);t.chmod(0o700);(t/'state').write_text('DIRTY\n')
  mountdev='/dev/block/mmcblk0p11' if case=='wrong_data_mount' else '/dev/block/mmcblk0p12'
  fs='f2fs' if case=='fallback_f2fs' else 'ext4'
  (root/'mounts').write_text(f'rootfs / rootfs rw 0 0\n{mountdev} {data} {fs} rw 0 0\n'+(f'/dev/block/dm-0 {data}/user/0 ecryptfs rw 0 0\n' if case=='fallback_overlay' else ''))
  zpath=root/'input.zip'
  with zipfile.ZipFile(zpath,'w') as z:
   for name,b in PAYLOAD.items():z.writestr('system/'+name,b)
   if case=='duplicate_archive_entry':z.writestr('system/product/priv-app/TestPackage/Test.apk',b'CONCATENATED_BAD_ENTRY')
  table=[]
  for name,b in PAYLOAD.items():
   h=hashlib.sha256(b).hexdigest()
   if case=='bad_hash' and name.endswith('Test.apk'):h='0'*64
   n='../outside/escape.xml' if case=='bad_table_path' and name.endswith('Test.apk') else name
   table.append('|'.join([h,str(len(b)),'0','0','0755' if name.startswith('addon.d/') else '0644','u:object_r:system_file:s0',n]))
  if case=='duplicate_table':table.append(table[-1])
  lib=TEMPLATE.replace('3dfaacc17df061913f47258a1aadcf1a42167f814de73de57c737b650340ecca',hashlib.sha256(Path('/usr/bin/true').read_bytes()).hexdigest()).replace('@@FLAVOR@@','minimal-gapps').replace('@@FILE_COUNT@@',str(len(table))).replace('@@PAYLOAD_BYTES@@',str(sum(map(len,PAYLOAD.values())))).replace('@@INPUT_SHA@@',hashlib.sha256(zpath.read_bytes()).hexdigest()).replace('@@FILES@@','\n'.join(table))
  assert '@@' not in lib
  lib=lib.rsplit('writer_main "$@"',1)[0]
  library=root/'library.sh';library.write_text(lib)
  harness=root/'harness.sh';harness.write_text('. '+shlex.quote(str(library))+'\n'+STUBS+'\nsetup_tools() { TOOLS=/usr/bin/true; }\nod() { /usr/bin/od "$@"; }\nfind() { /usr/bin/find "$@"; }\n'+f'\nROOT={shlex.quote(str(root))}\nCASE={case}\nEXT4_FEATURES="$ROOT/ext4features"\nDATA="$ROOT/data"\nTXROOT="$DATA/local/tmp/exynos4-google-services-recovery"\nMOUNTS="$ROOT/mounts"\nMNT="$ROOT/volume"\nS="$MNT/system"\nTMPROOT="$ROOT/work"\nFILES="$TMPROOT/files"\nwriter_main "$@"\n')
  if case=='preexisting_workspace':(root/'work').mkdir();(root/'work/foreign.txt').write_text('KEEP_WORKSPACE\n')
  r=subprocess.run(['sh',str(harness),'3','1',str(zpath)],capture_output=True,text=True,timeout=30)
  success=case in ['success','manual_rollback','fallback_plain'];assert (r.returncode==0)==success,(case,r.returncode,r.stdout,r.stderr)
  statefiles=list(txroot.glob('txn-*/state')) if txroot.exists() else []
  states=[f.read_text().strip() for f in statefiles]
  if case=='power_loss':
   assert r.returncode==-9 and states==['DIRTY'],(case,r.returncode,states,r.stdout,r.stderr)
   # Simulate recovery reboot: RAM work/mount view disappears, block data persists.
   import shutil
   (root/'volume/system').rename(source)
   (root/'volume').rmdir()
   (root/'mounts').write_text(f'rootfs / rootfs rw 0 0\n/dev/block/mmcblk0p12 {data} ext4 rw 0 0\n')
   shutil.rmtree(root/'work')
   txn=statefiles[0].parent
   r2=subprocess.run(['sh',str(txn/'rollback.sh'),'--rollback',str(txn)],capture_output=True,text=True,timeout=30)
   assert r2.returncode==0,(case,r2.stdout,r2.stderr)
   assert (txn/'state').read_text().strip()=='ROLLED_BACK' and old.read_bytes()==b'OLD_CONFIG\n'
   assert not (source/'product/priv-app/TestPackage/Test.apk').exists()
  elif case=='manual_rollback':
   assert states==['COMMITTED'],(case,states)
   txn=statefiles[0].parent;r2=subprocess.run(['sh',str(txn/'rollback.sh'),'--rollback',str(txn)],capture_output=True,text=True,timeout=30)
   assert r2.returncode==0,(case,r2.stdout,r2.stderr)
   assert (txn/'state').read_text().strip()=='ROLLED_BACK';assert old.read_bytes()==b'OLD_CONFIG\n' and stat.S_IMODE(old.stat().st_mode)==0o600
   assert not (source/'product/priv-app/TestPackage/Test.apk').exists()
  elif case in ['success','fallback_plain']:
   assert old.read_bytes()==b'NEW_CONFIG\n' and stat.S_IMODE(old.stat().st_mode)==0o644
   assert states==['COMMITTED'];assert (source/'product/priv-app/TestPackage/Test.apk').read_bytes()==PAYLOAD['product/priv-app/TestPackage/Test.apk']
  elif case in ['copy_failure','chcon_failure','signal_failure','directory_context_mismatch']:
   assert old.read_bytes()==b'OLD_CONFIG\n' and stat.S_IMODE(old.stat().st_mode)==0o600,(case,r.stdout,r.stderr)
   assert states==['ROLLED_BACK'],(case,states,r.stdout,r.stderr)
   if case=='directory_context_mismatch':assert 'Metadata mismatch path=' in r.stdout and 'unlabeled' in r.stdout
   assert not (source/'etc/exynos4-google-services/installed.json').exists()
  elif case=='foreign_change':
   assert old.read_bytes()==b'FOREIGN\n';assert states==['RECOVERY_REQUIRED'],(case,states)
  else:
   assert old.read_bytes()==b'OLD_CONFIG\n',case
   if case=='preexisting_workspace':assert (root/'work/foreign.txt').read_text()=='KEEP_WORKSPACE\n'
  assert (data/'media/0/TWRP/keep.txt').read_text()=='PERSONAL_BACKUP\n',case
  assert (source/'etc/keep.txt').read_text()=='UNRELATED\n',case
  assert (source/'addon.d/50-lineage.sh').read_text()=='BASELINE_ADDON\n',case
  results.append({'fixture':case,'exit':r.returncode,'states':states,'stdout':r.stdout,'stderr':r.stderr,'personal_backup_unchanged':True})
report={'fixture_count':len(results),'all_pass':True,'real_system_mounts_or_block_devices':False,'uid_gid_and_selinux_are_simulated':True,'apk_files_are_synthetic_for_transaction_fixtures':True,'results':results}
(P/'recovery-writer-fixtures.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',len(results),'full main-flow transaction fixtures')
