import copy
import unittest
from test_installer import profile
from test_local import digest
import installer as m
import android as a


class RuntimeTests(unittest.TestCase):
    def test_process_record_independently_pins_executable_argv_uid_context(self):
        self.assertTrue(hasattr(a,'validate_process'),'process validation missing')
        p=profile(); base=p['base']; exe=b'/system/bin/mksh'
        cmd=b'/system/bin/sh\0'+(base+'/service.sh').encode()+b'\0watch\0'
        record=('101 50 FICTIONAL-boot '+exe.hex()+' '+cmd.hex()+' 2000 u:r:shell:s0\n').encode()
        proc={'starttime':'50','exe':exe,'cmd':cmd,'uid':[2000]*4,'context':b'u:r:shell:s0'}
        result=a.validate_process('v2.watch',record,'FICTIONAL-boot',proc,p,exe)
        self.assertEqual(result['pid'],101)
        for key,value in [('starttime','51'),('exe',b'/system/bin/su'),('cmd',b'wrong\0'),
                          ('uid',[2000,0,2000,2000]),('context',b'u:r:su:s0')]:
            with self.subTest(key=key):
                bad=copy.deepcopy(proc);bad[key]=value
                with self.assertRaises(m.Refusal): a.validate_process('v2.watch',record,'FICTIONAL-boot',bad,p,exe)
        producer=b'/system/bin/sh\0'+(base+'/health-publisher.sh').encode()+b'\0watch\0'
        proc['cmd']=producer
        a.validate_process('health.watch',b'101 50 FICTIONAL-boot\n','FICTIONAL-boot',proc,p,exe)
        proc['cmd']=cmd
        with self.assertRaises(m.Refusal): a.validate_process('health.watch',b'101 50 FICTIONAL-boot','FICTIONAL-boot',proc,p,exe)
        for rec in [b'1 2 boot',record.replace(b'2000',b'0'),record+b' extra']:
            with self.assertRaises(m.Refusal): a.validate_process('v2.watch',rec,'FICTIONAL-boot',proc,p,exe)

    def test_native_replacement_requires_new_identity_and_same_pinned_server(self):
        self.assertTrue(hasattr(a,'validate_native_transition'),'native lifecycle boundary missing')
        old={'pid':201,'starttime':100,'exe':m.BIN+'adb','argv_sha256':'0'*64,'inode':'1:200',
             'uid':10123,'context':'u:r:untrusted_app:s0:c1,c2','listener':'127.0.0.1:5038'}
        new={**old,'pid':202,'starttime':110}
        a.validate_native_transition(old,new)
        a.validate_native_transition(old,old)
        for changes in [{'pid':201,'starttime':110},{'pid':202,'starttime':99}, {'exe':'/system/bin/adb'},
                        {'argv_sha256':'1'*64},{'inode':'1:201'},{'listener':'0.0.0.0:5038'}, {'uid':2000}]:
            with self.subTest(changes=changes):
                with self.assertRaises(m.Refusal): a.validate_native_transition(old,{**new,**changes})


if __name__=='__main__': unittest.main()
