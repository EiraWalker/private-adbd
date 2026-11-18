"""Read-only probe host-subprocess fixtures; every device identity is FICTIONAL."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import installer as installer

SCRATCH = Path(os.environ.get('TMPDIR') or tempfile.gettempdir())
IDENTITY = '''set -eu
getprop ro.serialno
id -u
id -Z
getenforce
cat /proc/sys/kernel/random/boot_id
getprop ro.build.version.sdk
getprop ro.product.cpu.abilist
getprop ro.product.cpu.abi
am get-current-user
getconf PAGE_SIZE'''
TOOLS = '''set -eu
for tool in sh getprop id getenforce cat am pm dumpsys run-as stat sha256sum readlink base64 cut grep flock getconf; do
  value=$(command -v "$tool" || :)
  printf '%s=%s\\n' "$tool" "$value"
done'''
PACKAGES = '''set -eu
set -o pipefail
pm list packages -U --user 0 com.termux | {
  LC_ALL=C grep -a -E -v '^package:com[.]termux[.][A-Za-z_][A-Za-z0-9_]*([.][A-Za-z_][A-Za-z0-9_]*)* uid:1[0-9]{4}$' || [ "$?" = 1 ]
}'''
METADATA = '''set -eu
set -o pipefail
dumpsys package com.termux | LC_ALL=C grep -a -E '^[[:space:]]*(versionCode=|userId=|appId=|flags=|pkgFlags=)|[^[:print:][:space:]]'
pm path --user 0 com.termux'''
RUN_AS = 'run-as com.termux id -u; result=$?; exit "$result"'


def phone(serial='FICTIONAL-PHONE-A', uid=10123, abi='arm64-v8a', sdk=35, page_size=4096):
    tools = 'sh getprop id getenforce cat am pm dumpsys run-as stat sha256sum readlink base64 cut grep flock getconf'.split()
    return {
        IDENTITY: [0, '\n'.join([serial, '2000', 'u:r:shell:s0', 'Enforcing',
                     '11111111-2222-4333-8444-555555555555', str(sdk), abi, abi, '0', str(page_size)])+'\n', ''],
        TOOLS: [0, ''.join(k+'=/system/bin/'+k+'\n' for k in tools), ''],
        PACKAGES: [0, 'package:com.termux uid:'+str(uid)+'\n', ''],
        METADATA: [0, '  userId='+str(uid)+'\n  versionCode=42 minSdk=26 targetSdk=35\n'
                      '  flags=[ DEBUGGABLE HAS_CODE ]\npackage:/data/app/fictional/com.termux/base.apk\n', ''],
        RUN_AS: [0, str(uid)+'\n', ''],
    }


class DiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-probe-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root/'fixed-controller.py'
        self.fixture.write_text('''import json,sys
from pathlib import Path
root=Path(__file__).parent
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\\n')
if args[:4]==['-s','FICTIONAL-USB-001','shell','-T']: args=['shell',*args[4:]]
if len(args)!=2 or args[0]!='shell': sys.exit(91)
responses=json.loads((root/'responses.json').read_text())
if args[1] not in responses: sys.exit(92)
code,out,err=responses[args[1]]
def raw(value): return bytes.fromhex(value['hex']) if isinstance(value,dict) else value.encode('utf-8')
sys.stdout.buffer.write(raw(out))
sys.stderr.buffer.write(raw(err))
sys.exit(code)
''')

    def invoke(self, responses=None, extra=(), command='probe', output='out'):
        (self.root/'responses.json').write_text(json.dumps(phone() if responses is None else responses))
        self.result = subprocess.run([sys.executable, '-S', '-B', str(HERE/'installer.py'), command,
                       '--transport-kind', 'controller', '--transport-argv',
                       json.dumps([sys.executable, '-S', '-B', str(self.fixture)]),
                       '--output', str(self.root/output), *extra], capture_output=True, timeout=45)
        return self.result

    def calls(self):
        path=self.root/'calls.jsonl'
        return [] if not path.exists() else [json.loads(line) for line in path.read_text().splitlines()]

    def test_probe_without_release_profile_sdk_or_known_uid_uses_real_controller(self):
        result=self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary=json.loads(result.stdout)
        self.assertEqual(summary['result'], 'probed')
        self.assertTrue(summary['read_only'])
        self.assertEqual(summary['device_calls'], len(self.calls()))
        self.assertNotIn('FICTIONAL-PHONE-A', result.stdout.decode())
        device=json.loads((self.root/'out/device.json').read_text())
        capability=json.loads((self.root/'out/capability.json').read_text())
        self.assertEqual(device['serial'], 'FICTIONAL-PHONE-A')
        self.assertEqual(device['termux']['uid'], 10123)
        self.assertEqual(capability['selection']['goarch'], 'arm64')
        self.assertFalse(capability['compatibility_verified'])
        self.assertNotIn('ready', capability)
        self.assertEqual([call[1] for call in self.calls()], [IDENTITY, TOOLS, PACKAGES, METADATA, RUN_AS])

    def test_probe_reports_16k_kernel_as_termux_apk_unsupported_without_writes(self):
        result=self.invoke(phone(page_size=16384))
        self.assertEqual(result.returncode,0,result.stderr)
        device=json.loads((self.root/'out/device.json').read_text())
        cap=json.loads((self.root/'out/capability.json').read_text())
        self.assertEqual(device['page_size'],16384)
        self.assertIs(type(device['page_size']),int)
        self.assertIn('termux-apk-page-size:requires-4096:observed-16384',cap['unsupported'])
        self.assertFalse(cap['compatibility_verified'])
        self.assertNotIn('ready',cap)
        self.assertEqual(cap['device_calls'],5)
        self.assertEqual(self.calls(),[['shell',code] for code in [IDENTITY,TOOLS,PACKAGES,METADATA,RUN_AS]])

    def test_probe_page_sizes_are_observations_not_sdk_guesses_or_compatibility(self):
        for page,sdk,ending in [(4096,35,'\n'),(16384,31,'\r\n'),(65536,99,'\n')]:
            with self.subTest(page=page,sdk=sdk):
                data=phone(page_size=page,sdk=sdk)
                if ending=='\r\n':data[IDENTITY][1]=data[IDENTITY][1].replace('\n',ending)
                result=self.invoke(data,output='page-'+str(page))
                self.assertEqual(result.returncode,0,result.stderr)
                device=json.loads((self.root/('page-'+str(page))/'device.json').read_text())
                cap=json.loads((self.root/('page-'+str(page))/'capability.json').read_text())
                self.assertEqual(device['page_size'],page)
                self.assertIs(type(device['page_size']),int)
                self.assertEqual(device['android_sdk'],sdk)
                self.assertEqual(cap['unsupported'],[] if page==4096 else
                                 ['termux-apk-page-size:requires-4096:observed-'+str(page)])
                self.assertFalse(cap['compatibility_verified'])
                self.assertEqual(cap['device_calls'],5)
                self.assertTrue(cap['commands']['getconf']['available'])
        self.assertEqual(len(self.calls()),15)
        self.assertEqual(self.calls(),[['shell',code] for code in [IDENTITY,TOOLS,PACKAGES,METADATA,RUN_AS]]*3)

    def test_probe_refuses_missing_invalid_or_failed_page_size_without_inference(self):
        for index,page in enumerate(('', 'unknown\n', '0\n', '8192\n', '04096\n', ' 4096\n',
                                     '4096 \n', '+4096\n', '4096.0\n', '4096\n4096\n',
                                     '4096\nextra\n', '4096\n\n', '4096\r', '4096\x00\n',
                                     '٤٠٩٦\n', 'nonzero', 'missing-command', 'stderr')):
            with self.subTest(page=repr(page)):
                data=phone()
                data[IDENTITY][1]=data[IDENTITY][1].rsplit('4096\n',1)[0]
                if page in ('nonzero','missing-command','stderr'):
                    data[IDENTITY][1]+='4096\n'
                    if page=='stderr':data[IDENTITY][2]='FICTIONAL getconf failed\n'
                    else:data[IDENTITY][0]=7 if page=='nonzero' else 127
                else:data[IDENTITY][1]+=page
                output='bad-page-'+str(index)
                result=self.invoke(data,output=output)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertFalse((self.root/output/'capability.json').exists())
                self.assertFalse((self.root/output/'device.json').exists())
        self.assertTrue(all(call==['shell',IDENTITY] for call in self.calls()))

    def test_probe_keeps_missing_getconf_capability_explicit_not_verified(self):
        data=phone();data[TOOLS][1]=data[TOOLS][1].replace('getconf=/system/bin/getconf','getconf=')
        result=self.invoke(data)
        self.assertEqual(result.returncode,0,result.stderr)
        cap=json.loads((self.root/'out/capability.json').read_text())
        self.assertIn('command-missing:getconf',cap['unsupported'])
        self.assertFalse(cap['commands']['getconf']['available'])
        self.assertFalse(cap['compatibility_verified'])

    def test_run_as_keeps_enclosing_shell_without_accepting_nonzero_uid_output(self):
        # Explicit fictional replay of a transport boundary, not real Android.
        guarded='run-as com.termux id -u; result=$?; exit "$result"'
        data=phone()
        data['run-as com.termux id -u']=[255,'10123\r\n','']
        data[guarded]=[0,'10123\r\n','']
        result=self.invoke(data)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.calls()[-1][1],guarded)
        data[guarded]=[255,'10123\r\n','']
        result=self.invoke(data,output='nonzero')
        self.assertEqual(result.returncode,2)
        self.assertFalse((self.root/'nonzero/capability.json').exists())


    def test_android15_zero_numeric_flags_are_noise_not_debuggable_evidence(self):
        data=phone()
        data[METADATA][1]=('    flags=0x0\n    flags=0x0\n  appId=10123\n'
                           '  versionCode=1010 minSdk=21 targetSdk=28\n'
                           '  flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]\n'
                           '  pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]\n'
                           '  appId=10123\npackage:/data/app/fictional/com.termux/base.apk\n')
        result=self.invoke(data)
        self.assertEqual(result.returncode,0,result.stderr)
        package=json.loads((self.root/'out/device.json').read_text())['termux']
        self.assertEqual(package['version'],1010)
        self.assertTrue(package['debuggable'])
        self.assertEqual(package['run_as'],'available')
        cap=json.loads((self.root/'out/capability.json').read_text())
        self.assertFalse(cap['compatibility_verified'])
        self.assertIn('maintenance-authorization',cap['not_verified'])
        self.assertEqual([call[1] for call in self.calls()],[IDENTITY,TOOLS,PACKAGES,METADATA,RUN_AS])

    def test_numeric_noise_does_not_bypass_run_as_uid_or_metadata_failure(self):
        for name in ('run-as-uid','metadata-exit','metadata-stderr','pm-error','nul','invalid-byte'):
            with self.subTest(name=name):
                data=phone()
                data[METADATA][1]='    flags=0x0\n'+data[METADATA][1]
                if name=='run-as-uid': data[RUN_AS][1]='10456\n'
                elif name=='metadata-exit': data[METADATA][0]=1
                elif name=='metadata-stderr': data[METADATA][2]='Permission Denial: fictional\n'
                elif name=='pm-error': data[METADATA][1]+='Error: fictional package manager failure\n'
                else:
                    raw=data[METADATA][1].encode()+ (b'    flags=0x0\x00\n' if name=='nul' else b'\xff\n')
                    data[METADATA][1]={'hex':raw.hex()}
                result=self.invoke(data,output='out-'+name)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertFalse((self.root/('out-'+name)/'capability.json').exists())

    def test_conflicting_debuggable_and_run_as_observations_refuse(self):
        data=phone()
        data[METADATA][1]=data[METADATA][1].replace('DEBUGGABLE ', '')
        result=self.invoke(data)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root/'out/capability.json').exists())

    def test_unrecognized_run_as_failure_refuses_instead_of_claiming_denied(self):
        data=phone();data[RUN_AS]=[91,'','FICTIONAL controller failure\n']
        result=self.invoke(data)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertFalse((self.root/'out/capability.json').exists())

    def test_second_phone_and_uninstalled_termux_are_reported_without_invented_uid(self):
        data=phone('FICTIONAL-PHONE-B', 10456, 'x86_64', 31)
        data[PACKAGES]=[0, '', '']
        result=self.invoke(data, ['--expected-serial', 'FICTIONAL-PHONE-B'])
        self.assertEqual(result.returncode, 0, result.stderr)
        device=json.loads((self.root/'out/device.json').read_text())
        capability=json.loads((self.root/'out/capability.json').read_text())
        self.assertEqual(device['serial'], 'FICTIONAL-PHONE-B')
        self.assertEqual(device['android_sdk'], 31)
        self.assertEqual(capability['selection']['goarch'], 'amd64')
        self.assertFalse(device['termux']['installed'])
        self.assertNotIn('uid', device['termux'])
        self.assertEqual(len(self.calls()), 3)

    def test_non_debuggable_split_and_denied_run_as_are_precise_unsupported(self):
        data=phone('FICTIONAL-PHONE-B', 10456, 'x86_64', 31)
        data[METADATA][1]=data[METADATA][1].replace('DEBUGGABLE ', '')+'package:/data/app/fictional/com.termux/split_config.x86_64.apk\n'
        data[RUN_AS]=[1, '', 'run-as: package not debuggable\n']
        result=self.invoke(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        device=json.loads((self.root/'out/device.json').read_text())
        capability=json.loads((self.root/'out/capability.json').read_text())
        self.assertEqual(device['termux']['uid'],10456)
        self.assertEqual(device['termux']['run_as'],'denied')
        self.assertEqual(set(capability['unsupported']),{'termux-not-debuggable','termux-split-apk','termux-run-as-denied'})


    def test_identity_and_expected_serial_fail_closed_over_real_subprocess(self):
        cases=[('uid', '2000', '0'), ('context', 'u:r:shell:s0', 'u:r:su:s0'),
               ('selinux', 'Enforcing', 'Permissive'), ('multidevice', 'FICTIONAL-PHONE-A', 'FICTIONAL-PHONE-A\nFICTIONAL-PHONE-B'),
               ('token', 'FICTIONAL-PHONE-A', ' FICTIONAL-PHONE-A'), ('nul', 'FICTIONAL-PHONE-A', 'FICTIONAL-PHONE-A\x00')]
        for name,old,new in cases:
            with self.subTest(name=name):
                data=phone();data[IDENTITY][1]=data[IDENTITY][1].replace(old,new)
                result=self.invoke(data, output='out-'+name)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertFalse((self.root/('out-'+name)/'capability.json').exists())
        data=phone();data[IDENTITY][1]={'hex':'ff'}
        result=self.invoke(data,output='non-utf8')
        self.assertEqual(result.returncode,2,result.stderr)
        result=self.invoke(extra=['--expected-serial','FICTIONAL-PHONE-B'],output='wrong-binding')
        self.assertEqual(result.returncode,2,result.stderr)
        result=self.invoke(extra=['--expected-serial',' FICTIONAL-PHONE-A'],output='invalid-binding')
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertFalse((self.root/'invalid-binding').exists())

    def test_probe_rejects_mutation_and_upgrade_flags_before_transport(self):
        for option in (['--execute'], ['--maintenance','FICTIONAL.json'], ['--profile','FICTIONAL.json'],
                       ['--release','FICTIONAL.json'], ['--apksigner-argv','[]'], ['--aapt-argv','[]'],
                       ['--checkpoint-sha256','0'*64], ['--transport-serial','FICTIONAL-USB-001']):
            with self.subTest(option=option):
                self.assertEqual(self.invoke(extra=option).returncode,2)
                self.assertEqual(self.calls(),[])
        for command in ('plan','inspect','apply','resume'):
            self.assertEqual(self.invoke(command=command).returncode,2)
            self.assertEqual(self.calls(),[])

    def test_adb_exact_selector_shell_false_timeout_and_no_sdk_through_host_fixture(self):
        import discovery
        (self.root/'responses.json').write_text(json.dumps(phone()))
        real_run=subprocess.run
        observed=[]
        def runner(command, **kwargs):
            if command[0]=='FICTIONAL-adb':
                observed.append((command,kwargs))
                return real_run([sys.executable,'-S','-B',str(self.fixture),*command[1:]],**kwargs)
            return real_run(command,**kwargs)
        args=installer.parser().parse_args(['probe','--transport-kind','adb','--transport-argv','["FICTIONAL-adb"]',
                  '--transport-serial','FICTIONAL-USB-001','--expected-serial','FICTIONAL-PHONE-A',
                  '--output',str(self.root/'adb-out')])
        with patch.object(installer,'SDK',side_effect=AssertionError('SDK must not be constructed')), \
             patch.object(installer,'Inputs',side_effect=AssertionError('release/profile must not be constructed')), \
             patch.object(discovery.subprocess,'run',side_effect=runner):
            result=installer.run(args)
        self.assertEqual(result['device_calls'],len(observed))
        self.assertEqual([args[0][1:5] for args in observed],[['-s','FICTIONAL-USB-001','shell','-T']]*len(observed))
        for command,kwargs in observed:
            self.assertFalse(kwargs['shell'])
            self.assertEqual(kwargs['timeout'],15)
            self.assertIsNone(kwargs['input'])
            self.assertTrue(kwargs['capture_output'])
            self.assertIn(command[-1],(IDENTITY,TOOLS,PACKAGES,METADATA,RUN_AS))
        device=json.loads((self.root/'adb-out/device.json').read_text())
        self.assertEqual(device['serial'],'FICTIONAL-PHONE-A')
        self.assertEqual(device['transport']['serial'],'FICTIONAL-USB-001')

    def test_missing_tools_unknown_abi_and_multiuser_do_not_claim_compatibility(self):
        data=phone(abi='FICTIONAL-ABI',sdk=99)
        data[IDENTITY][1]=data[IDENTITY][1].replace('\n0\n','\n10\n')
        data[TOOLS][1]=data[TOOLS][1].replace('pm=/system/bin/pm','pm=')
        result=self.invoke(data)
        self.assertEqual(result.returncode,0,result.stderr)
        cap=json.loads((self.root/'out/capability.json').read_text())
        device=json.loads((self.root/'out/device.json').read_text())
        self.assertIsNone(cap['selection']['goarch'])
        self.assertFalse(cap['compatibility_verified'])
        self.assertEqual(set(cap['unsupported']),{'unknown-primary-abi','command-missing:pm','non-primary-current-user:fixed-termux-prefix'})
        self.assertIsNone(device['termux']['installed'])
        self.assertNotIn('uid',device['termux'])
        self.assertEqual(len(self.calls()),2)


def android_producer_shell():
    """Host-only fixture: Android's fixed producers require non-POSIX pipefail."""
    for name in ('mksh', 'bash'):
        shell = shutil.which(name)
        if shell is not None:
            # Windows' system bash.exe launches WSL, not a native host shell.
            if (sys.platform == 'win32' and name == 'bash' and
                    Path(shell).resolve() == (Path(os.environ.get('SystemRoot', 'C:/Windows'))/
                                               'System32/bash.exe').resolve()):
                continue
            return shell
    raise unittest.SkipTest('requires host mksh or bash with pipefail for Android producer fixture; arbitrary sh is insufficient')


class AndroidProducerShellSelection(unittest.TestCase):
    def test_mksh_is_preferred_over_bash_and_arbitrary_sh(self):
        available = {'mksh': '/fixture/mksh', 'bash': '/fixture/bash', 'sh': '/fixture/sh'}
        with patch.object(shutil, 'which', side_effect=available.get):
            self.assertEqual(android_producer_shell(), '/fixture/mksh')

    def test_bash_is_used_when_mksh_is_absent(self):
        available = {'bash': '/fixture/bash', 'sh': '/fixture/sh'}
        with patch.object(shutil, 'which', side_effect=available.get):
            self.assertEqual(android_producer_shell(), '/fixture/bash')

    def test_arbitrary_sh_alone_does_not_claim_android_pipefail_support(self):
        with patch.object(shutil, 'which', side_effect={'sh': '/fixture/dash'}.get):
            with self.assertRaisesRegex(unittest.SkipTest, 'mksh or bash.*pipefail'):
                android_producer_shell()

    def test_windows_wsl_bash_launcher_is_not_a_native_shell(self):
        windows = SCRATCH/'fictional-windows'
        available = {'bash': str(windows/'System32/bash.exe'), 'sh': '/fixture/sh'}
        with patch.object(sys, 'platform', 'win32'), \
             patch.dict(os.environ, {'SystemRoot': str(windows)}), \
             patch.object(shutil, 'which', side_effect=available.get):
            with self.assertRaisesRegex(unittest.SkipTest, 'mksh or bash.*pipefail'):
                android_producer_shell()


class DiscoveryValidation(unittest.TestCase):
    @unittest.skipUnless(shutil.which('sh'),'requires host shell for fictional identity producer')
    def test_fixed_identity_shell_reads_actual_kernel_page_size(self):
        import discovery as d
        setup=('getprop() { case "$1" in ro.serialno) printf "FICTIONAL-PHONE-A\\n" ;; '
               'ro.build.version.sdk) printf "35\\n" ;; ro.product.cpu.*) printf "arm64-v8a\\n" ;; '
               '*) return 91 ;; esac; }\n'
               'id() { case "$1" in -u) printf "2000\\n" ;; -Z) printf "u:r:shell:s0\\n" ;; '
               '*) return 92 ;; esac; }\ngetenforce() { printf "Enforcing\\n"; }\n'
               'cat() { printf "11111111-2222-4333-8444-555555555555\\n"; }\n'
               'am() { printf "0\\n"; }\n'
               'getconf() { [ "$#" = 1 ] && [ "$1" = PAGE_SIZE ] || return 93; printf "16384\\n"; }\n')
        shell=shutil.which('sh');assert shell is not None
        result=subprocess.run([shell,'-c',setup+d.IDENTITY],capture_output=True,timeout=15,shell=False)
        self.assertEqual(result.returncode,0,result.stderr)
        device=d.identity(d.lines(result.stdout),None)
        self.assertIn('page_size',device)
        self.assertEqual(device['page_size'],16384)

    @unittest.skipUnless(shutil.which('sh'),'requires host shell for fictional tool producer')
    def test_fixed_tools_shell_includes_getconf_capability(self):
        import discovery as d
        shell=shutil.which('sh');assert shell is not None
        result=subprocess.run([shell,'-c','command() { printf "/system/bin/%s" "$2"; }\n'+d.TOOLS],
                              capture_output=True,timeout=15,shell=False)
        self.assertEqual(result.returncode,0,result.stderr)
        commands=d.tools(d.lines(result.stdout))
        self.assertIn('getconf',commands)
        self.assertEqual(commands['getconf'],{'available':True,'path':'/system/bin/getconf'})

    def test_legacy_options_can_still_precede_command(self):
        args=installer.parser().parse_args(['--profile','FICTIONAL-profile.json','--release','FICTIONAL-release.json',
                                         '--output','FICTIONAL-output','plan'])
        self.assertEqual(args.command,'plan')
        self.assertEqual(args.apksigner_argv,'["apksigner"]')
        self.assertFalse(args.execute)
        args=installer.parser().parse_args(['plan','--profile','FICTIONAL-profile.json','--release','FICTIONAL-release.json',
                                         '--output','FICTIONAL-output','--apksigner-argv',''])
        self.assertEqual(args.apksigner_argv,'')

    def test_strict_byte_parser_accepts_only_line_crlf_without_token_normalization(self):
        import discovery as d
        self.assertEqual(d.lines(b'FICTIONAL\r\n2000\r\n'),['FICTIONAL','2000'])
        for raw in (b'\xff', b'FICTIONAL\x00', b'FICTIONAL\r', b'FICTIONAL\v', b'a'*65537):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(d.Refusal):d.lines(raw)
        self.assertEqual(d.lines(b' FICTIONAL '),[' FICTIONAL '])

    def test_fixed_package_shell_preserves_ambiguous_pm_stdout_for_host_refusal(self):
        import discovery as d
        result=subprocess.run([android_producer_shell(),'-c', "pm() { printf '%s\\n' 'FICTIONAL unexpected package-manager output'; }\n"+d.PACKAGES],
                              capture_output=True,timeout=15,shell=False)
        self.assertEqual(result.returncode,0,result.stderr)
        with self.assertRaises(d.Refusal):d.package_inventory(d.lines(result.stdout))

    def test_fixed_package_shell_filters_only_target_and_accepts_absence(self):
        import discovery as d
        shell=android_producer_shell()
        for output, expected in [('package:com.termux uid:10123\npackage:com.termux.api uid:10456\n', b'package:com.termux uid:10123\n'),('',b'')]:
            # Test-only pm function; production code has no callback or PATH override.
            setup="pm() { printf '%s' "+repr(output).replace('\\n','\n')+"; }\n"
            result=subprocess.run([shell,'-c',setup+d.PACKAGES],capture_output=True,timeout=15,shell=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,expected)

    def test_shell_does_not_hide_empty_pm_lines_or_non_utf8_metadata(self):
        import discovery as d
        shell=android_producer_shell()
        setup="pm() { printf '\\npackage:com.termux uid:10123\\n'; }\n"
        r=subprocess.run([shell,'-c',setup+d.PACKAGES],capture_output=True,timeout=15,shell=False)
        self.assertEqual(r.returncode,0,r.stderr)
        with self.assertRaises(d.Refusal):d.package_inventory(d.lines(r.stdout))
        setup="dumpsys() { printf '  userId=10123\\n  versionCode=42 minSdk=26\\n  flags=[ DEBUGGABLE HAS_CODE ]\\n\\377garbage\\n'; }\npm() { printf 'package:/data/app/fictional/com.termux/base.apk\\n'; }\n"
        r=subprocess.run([shell,'-c',setup+d.METADATA],capture_output=True,timeout=15,shell=False)
        self.assertEqual(r.returncode,0,r.stderr)
        with self.assertRaises(d.Refusal):d.package_metadata(d.lines(r.stdout),{'uid':10123})

    def test_malformed_sibling_names_and_uids_are_not_silently_filtered(self):
        import discovery as d
        shell=android_producer_shell()
        for sibling in ('package:com.termux..api uid:10456','package:com.termux. uid:0','package:com.termux.api uid:0'):
            setup="pm() { printf '%s\\n' 'package:com.termux uid:10123' '"+sibling+"'; }\n"
            r=subprocess.run([shell,'-c',setup+d.PACKAGES],capture_output=True,timeout=15,shell=False)
            with self.subTest(sibling=sibling):
                self.assertEqual(r.returncode,0,r.stderr)
                with self.assertRaises(d.Refusal):d.package_inventory(d.lines(r.stdout))

    def test_package_uid_duplicates_accept_consistency_and_refuse_conflicts(self):
        import discovery as d
        package=d.package_inventory(['package:com.termux uid:10456']*2)
        values=phone(uid=10456)[METADATA][1].splitlines()
        d.package_metadata(values+['  appId=10456'],package)
        self.assertEqual(package['uid'],10456)
        for bad in (values+['  appId=10457'],values+['  versionCode=42'],values+['  flags=[ HAS_CODE ]']):
            with self.assertRaises(d.Refusal):d.package_metadata(bad,{'uid':10456})
        with self.assertRaises(d.Refusal):d.package_inventory(['package:com.termux uid:10456','package:com.termux uid:10457'])
        with self.assertRaises(d.Refusal):d.package_inventory(['error: more than one device'])

    def test_zero_numeric_flags_never_supply_or_override_canonical_flags(self):
        import discovery as d
        values=phone()[METADATA][1].splitlines()
        noise=['    flags=0x0','\tflags=0x0']
        missing=[v for v in values if 'flags=' not in v]
        with self.assertRaises(d.Refusal):d.package_metadata(noise+missing,{'uid':10123})
        package={'uid':10123}
        d.package_metadata(noise+[v.replace('DEBUGGABLE ','') for v in values],package)
        self.assertFalse(package['debuggable'])
        for bad in (values+['  appId=10456'],values+['  versionCode=42'],
                    values+['  pkgFlags=[ HAS_CODE ]'],values+[values[-1]]):
            with self.subTest(bad=bad):
                with self.assertRaises(d.Refusal):d.package_metadata(noise+bad,{'uid':10123})

    def test_numeric_flags_exception_is_exact_not_an_unknown_line_skip(self):
        import discovery as d
        values=phone()[METADATA][1].splitlines()
        for extra in ('flags=0x1','flags=0x00','flags=0X0','flags=0','flags=0x',
                      'flags=0x0 ','flags=0x0 DEBUGGABLE','pkgFlags=0x0',
                      'flags =0x0','flags=0x0\r','unknown=0x0','',
                      'Permission Denial: fictional','Error: fictional pm failure'):
            with self.subTest(extra=extra):
                with self.assertRaises(d.Refusal):
                    d.package_metadata(['    flags=0x0']+values+[extra],{'uid':10123})

    def test_metadata_shell_keeps_zero_noise_and_full_stream_byte_failure_gates(self):
        import discovery as d
        shell=android_producer_shell()
        assert shell is not None
        setup=("dumpsys() { printf '    flags=0x0\\n    flags=0x0\\n  appId=10123\\n"
               "  versionCode=1010 minSdk=21 targetSdk=28\\n  flags=[ DEBUGGABLE HAS_CODE ]\\n"
               "  pkgFlags=[ DEBUGGABLE HAS_CODE ]\\n  appId=10123\\n'; EXTRA; }\n"
               "pm() { printf 'package:/data/app/fictional/com.termux/base.apk\\n'; }\n")
        for extra in (':',"printf 'unrelated\\000line\\n'","printf '\\377unrelated\\n'"):
            with self.subTest(extra=extra):
                r=subprocess.run([shell,'-c',setup.replace('EXTRA',extra)+d.METADATA],
                                 capture_output=True,timeout=15,shell=False)
                self.assertEqual(r.returncode,0,r.stderr)
                if extra==':':
                    package={'uid':10123}
                    d.package_metadata(d.lines(r.stdout),package)
                    self.assertTrue(package['debuggable'])
                else:
                    with self.assertRaises(d.Refusal):d.lines(r.stdout)
        for setup in ("dumpsys() { printf '  flags=[ DEBUGGABLE ]\\n'; return 7; }\npm() { return 0; }\n",
                      "dumpsys() { printf '  flags=[ DEBUGGABLE ]\\n'; }\npm() { return 7; }\n"):
            r=subprocess.run([shell,'-c',setup+d.METADATA],capture_output=True,timeout=15,shell=False)
            self.assertNotEqual(r.returncode,0,r.stderr)

    def test_ambiguous_output_and_transport_selectors_fail_closed(self):
        import discovery as d
        original=phone()[IDENTITY][1].splitlines()
        for values in (original+['extra'],original[:6]+['arm64-v8a,arm64-v8a']+original[7:],
                       original[:7]+['x86_64']+original[8:]):
            with self.assertRaises(d.Refusal):d.identity(values,None)
        for transport in ({'kind':'adb','argv':['adb']},{'kind':'adb','argv':['adb','-d'],'serial':'FICTIONAL'},
                          {'kind':'controller','argv':['controller'],'serial':'FICTIONAL'},
                          {'kind':'controller','argv':['controller\n']},{'kind':'adb','argv':['adb'],'serial':' FICTIONAL'}):
            with self.assertRaises(d.Refusal):d.validate_transport(transport)
        class Out:
            def event(self,*args):pass
        t=d.ProbeTransport({'kind':'controller','argv':['FICTIONAL']},Out())
        with self.assertRaises(d.Refusal):t.read('id -u; arbitrary-callback')
        self.assertEqual(t.calls,0)
        with patch.object(d.subprocess,'run',side_effect=subprocess.TimeoutExpired(['FICTIONAL'],15)):
            with self.assertRaises(d.Refusal):t.read(IDENTITY)
        self.assertEqual(t.calls,1)


if __name__ == '__main__': unittest.main()
