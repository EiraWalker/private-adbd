"""Private local evidence; never put this output in a source checkout."""
from __future__ import annotations
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from contextlib import contextmanager

from common import Refusal, need, sha

LABELS = frozenset(('status','package','installed-apk','identity','read','metadata','control',
                    'clock','process','invariant','keys-stat','listeners','lock-probe',
                    'acquire-lock','stage-reserve','push','stage-check','stage-seal','install','payload',
                    'native-start','legacy-remove','stage-clean','lock-release','presence'))


def no_links(path):
    path = Path(path)
    need('..' not in path.parts, 'host parent path component')
    path = path.absolute()
    for item in [path, *path.parents]:
        if item.exists() or item.is_symlink():
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not
                 (getattr(info, 'st_file_attributes', 0) & 0x400), 'host symlink/reparse point')
    # Validate the supplied ancestors before canonicalizing, so neither a
    # symlink nor a Windows path alias can bypass repository containment.
    return path.resolve()


def sync_directory(path):
    if os.name == 'posix':
        fd = os.open(path, os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
        try: os.fsync(fd)
        finally: os.close(fd)


def windows_acl(path, create=False):
    # Fixed local OS tools only. No shell or credential material is involved.
    sid = subprocess.check_output(['whoami','/user','/fo','csv','/nh'], text=True).strip().split(',')[-1].strip('"')
    need(re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+',sid) is not None, 'current user SID')
    literal = str(path).replace("'", "''")
    if create:
        # mkdir(0700) on recent Python adds an explicit Administrators ACE.
        # Only this newly created directory is changed; verify the exact result.
        r = subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                            '*'+sid+':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F',
                            '/remove:g', '*S-1-5-32-544', '*S-1-3-4'], capture_output=True)
        need(r.returncode == 0, 'host ACL setup')
    # Check both the directory and every existing evidence file in one local call.
    # A protected parent does not neutralize an explicit broad child-file ACE.
    code = ("$ErrorActionPreference='Stop'; function SnapshotAcl($target) { $a=Get-Acl -LiteralPath $target; "
            "[pscustomobject]@{protected=$a.AreAccessRulesProtected; owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; "
            "rules=@($a.Access | ForEach-Object { [pscustomobject]@{sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;type=$_.AccessControlType.ToString();rights=[int]$_.FileSystemRights} })} }; "
            "[pscustomobject]@{root=(SnapshotAcl '"+literal+"'); children=@(Get-ChildItem -Force -LiteralPath '"+literal+"' | ForEach-Object { SnapshotAcl $_.FullName })} | ConvertTo-Json -Depth 7 -Compress")
    try:
        data = json.loads(subprocess.check_output(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],stderr=subprocess.PIPE))
        need(data['root']['protected'] is True, 'host ACL inheritance')
        for entry in [data['root'],*data['children']]:
            rules=entry['rules']
            need(entry['owner'] in (sid,'S-1-5-18') and
                 {r['sid'] for r in rules} == {sid,'S-1-5-18'} and
                 all(r['type']=='Allow' and r['rights']==2032127 for r in rules), 'host ACL verification')
    except (KeyError, ValueError, TypeError, subprocess.SubprocessError):
        raise Refusal('host ACL verification') from None


class PrivateOutput:
    def __init__(self, path, create):
        self.path = no_links(path)
        need(not self.path.is_relative_to(Path(__file__).resolve().parents[1]), 'private output inside repository')
        if create:
            need(not self.path.exists(), 'output already exists')
            need(self.path.parent.is_dir(), 'output parent must already exist')
            self.path.mkdir(mode=0o700)
            if os.name == 'nt': windows_acl(self.path, create=True)
            sync_directory(self.path.parent)
        need(self.path.is_dir(), 'output directory missing')
        self.verify()

    def verify(self):
        no_links(self.path)
        if os.name == 'nt': windows_acl(self.path)
        else:
            st = self.path.stat()
            need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode)==0o700, 'private output permissions')
        for path in self.path.iterdir():
            no_links(path)
            st=path.stat()
            need(path.is_file() and st.st_nlink==1, 'output file identity')
            if os.name == 'posix':
                need(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600, 'private file permissions')

    def target(self, name):
        need(isinstance(name,str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,120}',name), 'output filename')
        path=self.path/name
        no_links(path)
        if path.exists(): need(path.is_file() and path.stat().st_nlink==1,'output hardlink/type')
        return path

    @contextmanager
    def session(self):
        path=self.target('host-session.lock')
        fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        acquired=False
        try:
            info=os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'host lock identity')
            try:
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:raise Refusal('another local installer owns this output session') from None
            acquired=True
            if info.st_size==0:
                os.write(fd,b'0');os.fsync(fd);sync_directory(self.path)
            yield
        finally:
            if acquired:
                os.lseek(fd,0,os.SEEK_SET)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
                else:
                    import fcntl
                    fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)

    def raw(self, name, data):
        path=self.target(name)
        try: fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError: raise Refusal('backup already exists') from None
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        sync_directory(self.path)

    def write(self, name, obj):
        data=(json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()
        temp='pending-'+uuid.uuid4().hex+'.json'
        self.raw(temp,data)
        os.replace(self.target(temp),self.target(name))
        sync_directory(self.path)

    def event(self,label,exit_code,stdout,stderr):
        need(label in LABELS,'event label')
        obj={'time':dt.datetime.now(dt.timezone.utc).isoformat(),'label':label,'exit':exit_code,
             'stdout_bytes':len(stdout),'stdout_sha256':sha(stdout),
             'stderr_bytes':len(stderr),'stderr_sha256':sha(stderr)}
        path=self.target('events.jsonl')
        fd=os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600)
        with os.fdopen(fd,'ab') as f:
            f.write((json.dumps(obj,sort_keys=True)+'\n').encode()); f.flush(); os.fsync(f.fileno())
        sync_directory(self.path)
