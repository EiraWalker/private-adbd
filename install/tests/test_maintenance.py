import copy
import datetime as dt
import unittest
from test_installer import profile
import installer as m

NOW = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def maintenance():
    return {'schema': 1, 'profile_sha256': '0'*64, 'release_sha256': '1'*64,
            'serial': 'FICTIONAL-SERIAL-001', 'owner': 'FICTIONAL-owner-session',
            'ready': True, 'released': True, 'no_parallel': True,
            'issued_at': NOW.isoformat(), 'expires_at': (NOW+dt.timedelta(minutes=10)).isoformat()}


class MaintenanceTests(unittest.TestCase):
    def test_maintenance_binds_actual_owner_and_short_window(self):
        self.assertTrue(hasattr(m,'validate_maintenance'), 'maintenance gate missing')
        m.validate_maintenance(maintenance(), '0'*64, '1'*64, profile()['serial'], now=NOW)
        for key, value in [('ready',False),('released',False),('no_parallel',False),('owner',''),
                           ('profile_sha256','2'*64),('release_sha256','3'*64),('serial','FICTIONAL-other'),
                           ('issued_at','2030-01-01T00:00:00'),('expires_at','2030-01-01T01:00:00+00:00'),
                           ('expires_at',NOW.isoformat()),('unknown',True)]:
            with self.subTest(key=key):
                obj=maintenance(); obj[key]=value
                with self.assertRaises(m.Refusal):
                    m.validate_maintenance(obj, '0'*64, '1'*64, profile()['serial'], now=NOW)


if __name__ == '__main__': unittest.main()
