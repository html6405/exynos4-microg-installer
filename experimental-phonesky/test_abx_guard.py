#!/usr/bin/env python3
from pathlib import Path
import subprocess,struct,json
P=Path(__file__).parent
class Writer:
 def __init__(self):self.b=bytearray(b'ABX\0\x10');self.pool={}
 def utf(self,v):v=v.encode() if isinstance(v,str) else v;return struct.pack('>H',len(v))+v
 def intern(self,v):
  if v in self.pool:return struct.pack('>H',self.pool[v])
  self.pool[v]=len(self.pool);return b'\xff\xff'+self.utf(v)
 def start(self,n):self.b+=b'\x32'+self.intern(n)
 def end(self,n):self.b+=b'\x33'+self.intern(n)
 def attr(self,n,v,typ=32):self.b+=bytes([typ|15])+self.intern(n)+(self.utf(v) if typ in [32,64,80] else self.intern(v))
 def finish(self):return bytes(self.b)+b'\x11'
def document(path=None,value='com.google.android.gms',attr='packageName',typ=32,extra=False):
 w=Writer();w.start('packages')
 if path:
  for n in path:w.start(n)
  w.attr(attr,value,typ)
  if extra:w.attr(attr,value,typ)
  for n in path[::-1]:w.end(n)
 w.end('packages');return w.finish()
legacy=['domain-verifications-legacy','user-states'];cases=[]
def case(n,b,ok):cases.append((n,b,ok))
case('clean',document(),True)
for name in ['com.google.android.gms','com.android.vending','com.google.android.gsf','com.google.android.gsf.login']:
 case('allowed_history_'+name,document(legacy,name),True)
 case('active_package_'+name,document(['package'],name,'name'),False)
case('interned_history',document(legacy,typ=48),True)
case('wrong_history_attribute',document(legacy,attr='name'),False)
case('wrong_parent',document(['domain-verifications','user-states']),False)
case('nested_package',document(['domain-verifications-legacy','user-states','package'],attr='name'),False)
case('suffix_not_exact',document(legacy,'com.google.android.gms.permission.AD_ID'),False)
case('duplicate_attribute',document(legacy,extra=True),False)
case('byte_hidden_identity',document(['package'],attr='name',typ=64),False)
case('wrong_magic',b'ABX\1'+document()[4:],False)
case('invalid_pool',b'ABX\0\x10\x32\x00\x01',False)
case('missing_end',document()[:-1],False)
case('trailing_bytes',document()+b'JUNK',False)
case('truncated',document(legacy)[:-7],False)
case('overlong_utf8',document(['package'],b'com\xc0\xaegoogle.android.gms','name'),False)
case('unicode_unrelated',document(['package'],'org.example.\u00e4','name'),True)
case('mixed_text',document()[:-4]+b'\x24\x00\x01x'+document()[-4:],False)
w=Writer();w.start('packages');w.end('packages');w.start('packages');w.end('packages');case('double_root',w.finish(),False)
case('sensitive_unrelated_attribute',document(['package'],'com.google.android.gms','installer'),False)
w=Writer();w.start('packages');w.start('domain-verifications-legacy');w.start('user-states');w.attr('packageName','com.google.android.gms',48);w.end('user-states');w.end('domain-verifications-legacy');w.start('package');w.attr('name','com.google.android.gms',48);w.end('package');w.end('packages');case('interned_history_reused_active',w.finish(),False)
case('truncated_typed_blob',document(['package'],attr='name',typ=64)[:-12],False)

def source_case(flag, value='com.android.vending', attr='installInitiator'):
 w=Writer();w.start('packages');w.start('package')
 w.attr('name','org.example.client')
 if flag is not None:
  w.b+=bytes([0xcf if flag else 0xdf])+w.intern('installInitiatorUninstalled')
 w.attr(attr,value,48)
 w.end('package');w.end('packages')
 return w.finish()
case('store_history_uninstalled', source_case(True), True)
case('store_history_missing_marker', source_case(None), False)
case('store_history_false_marker', source_case(False), False)
case('gms_as_initiator', source_case(True, 'com.google.android.gms'), False)
case('store_as_current_installer', source_case(True, attr='installer'), False)

case('supervision_history',document(legacy,'com.google.android.gms.supervision'),True)
case('supervision_active',document(['package'],'com.google.android.gms.supervision','name'),False)
results=[]
for n,b,ok in cases:
 decimal=' '.join(map(str,b))+'\n';r=subprocess.run(['awk','-f',str(P/'package-state-abx.awk')],input=decimal,text=True,capture_output=True,env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
 assert (r.returncode==0)==ok,(n,r.returncode,r.stderr)
 results.append({'fixture':n,'allowed':ok,'exit':r.returncode})
(P/'abx-guard-fixtures.json').write_text(json.dumps({'count':len(results),'all_pass':True,'results':results},indent=2)+'\n');print('PASS',len(results),'ABX guard fixtures')
