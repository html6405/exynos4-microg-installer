from pathlib import Path
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

work = Path(__file__).resolve().parent
builds = work.parent / 'minimal-gapps-20261122/recovery-test-builds'
inputs = [
    ('microg-companion', 'r4', 'c7794d935e24d5235cd6ae81df33c7d8d0115f97066e9d8ac4ba7b4a63bb65ab'),
    ('minimal-gapps', 'r5', '6db902bff7283d30696954458307b18429f87d5ca2ad0fa98d342826f0a618cc'),
]
marker = 'etc/exynos4-google-services/installed.json'
addon = 'addon.d/50-exynos4-google-services.sh'
store = 'product/priv-app/Phonesky/Phonesky.apk'
policy = 'product/etc/permissions/privapp-permissions-google-product.xml'

def digest(data):
    return hashlib.sha256(data).hexdigest()

files = {}
components = []
for flavor, revision, pin in inputs:
    archive = builds / f'Exynos4-LOS23-{flavor}-TWRP-{revision}-TEST-UNSIGNED.zip'
    assert digest(archive.read_bytes()) == pin
    with ZipFile(archive) as z:
        manifest = json.loads(z.read('system/' + marker))
        selected = 'com.google.android.gms' if flavor == 'microg-companion' else 'com.android.vending'
        matches = [c for c in manifest['components'] if c['package'] == selected]
        assert len(matches) == 1
        components.extend(matches)
        if flavor == 'microg-companion':
            names = [n for n in z.namelist() if
                     n.startswith('system/product/priv-app/Exynos4MicroGServices/') or
                     n in ('system/product/etc/permissions/privapp-permissions-exynos4-microg-services.xml',
                           'system/product/etc/sysconfig/exynos4-microg.xml')]
            files.update({n.removeprefix('system/'): z.read(n) for n in names})
        else:
            files[store] = z.read('system/' + store)
            assert digest(files[store]) == 'ced7b35522efe02129f37b702a00a5a0fdc73c99cdfcc1ac5f1d17ecb4d47fac'
            root = ET.Element('permissions')
            blocks = [b for b in ET.fromstring(z.read('system/' + policy)).findall('privapp-permissions')
                      if b.get('package') == selected]
            assert len(blocks) == 1
            root.append(blocks[0])
            ET.indent(root)
            files[policy] = ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'
            # Keep the exact Store-only power exemption from the tested GApps source.
            config = ET.fromstring(z.read('system/product/etc/sysconfig/google.xml'))
            allow = [n for n in config.findall('allow-in-power-save-except-idle')
                     if n.get('package') == selected]
            assert len(allow) == 1 and allow[0].attrib == {'package': 'com.android.vending'}
            sysconfig = ET.Element('config')
            sysconfig.append(allow[0])
            ET.indent(sysconfig)
            files['product/etc/sysconfig/exynos4-phonesky.xml'] = (
                ET.tostring(sysconfig, encoding='utf-8', xml_declaration=True) + b'\n')
            old_addon = z.read('system/' + addon).decode()
names = '\n'.join(sorted([*files, marker]))
new_addon, count = re.subn(r"(<<'EXYNOS4_FILES'\n).*?(\nEXYNOS4_FILES)", 
                          lambda m: m[1] + names + m[2], old_addon, count=1, flags=re.S)
assert count == 1
files[addon] = new_addon.encode()
manifest = {'schema': 1, 'flavor': 'microg-phonesky', 'os_sdk': 36, 'abi': 'armeabi-v7a',
            'components': components, 'ota_validation': {'status': 'UNVERIFIED'},
            'candidate_not_flashable': True,
            'files': [{'logical_path': n, 'sha256': digest(b), 'size': len(b),
                       'uid': 0, 'gid': 0, 'mode': '0755' if n == addon else '0644',
                       'selinux_context': 'u:object_r:system_file:s0'} for n,b in sorted(files.items())]}
files[marker] = (json.dumps(manifest, indent=2) + '\n').encode()
output = work/'microg-phonesky-r7.payload.zip'
with ZipFile(output,'w',compression=ZIP_DEFLATED) as z:
    for n,b in sorted(files.items()):
        i = ZipInfo('system/' + n, (2026, 11, 23, 0, 0, 0))
        i.compress_type = ZIP_DEFLATED
        z.writestr(i, b)
print(digest(output.read_bytes()))
