"""종료가 확인된 Windows 캡처의 같은 fd 검증·케이스 등록.

원본 경로를 다시 열지 않는다. 최종 파일은 배타 생성하고 commit 여부가 불명확한
출력을 임의 삭제하지 않는다. 실행 owner와 케이스 원장의 commit 사실은 영수증으로 연결한다.
"""
from __future__ import annotations

import os
import stat
import time

from pweh import safeio
from pweh.errors import PwehError

_CODES = frozenset(('invalid','failed','busy','cleanup_unknown','cancelled','timeout','output_limit',
    'bad_zip','unsupported','metadata_mismatch','limit','io_failed','check_failed','empty_capture',
    'no_output','publication_failed','artifact_exists','post_commit_failed'))


def error(code='failed', *, data=None):
    if type(code) is str and code.startswith('sigrok_capture_'):
        code = code[len('sigrok_capture_'):]
    if type(code) is not str or code not in _CODES:
        code = 'failed'
    return PwehError('Windows OLS 캡처 또는 결과 등록을 완료하지 못했습니다.',
                     code='sigrok_capture_'+code, data=data)


def public_error(exc):
    code = getattr(exc, 'code', None)
    if type(code) is not str:
        return error()
    return error({'artifact_timeout':'timeout','artifact_exists':'artifact_exists'}.get(code,code))


def _identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def _directory(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid)


class CapturePublisher:
    """하나의 worker 전용 게시 기록. audit 실패 뒤에도 artifact/receipt를 보존한다."""
    def __init__(self, case, command, *, output_name, bundle_meta, job_context=None, cli_failed=False):
        self.case, self.command, self.output_name = case, command, output_name
        self.bundle_meta, self.job_context = bundle_meta, job_context
        self.cli_failed = cli_failed
        self.result = None
        self.receipt = None
        self.artifact = None
        self.path = None
        self.precommit_cancelled = False
        self.called = False

    def __call__(self, source, *, exit, deadline, cancel):
        from pweh.sigrok_srzip import inspect_capture_fd
        from .windows_capture import CapturePublication
        if self.called:
            raise error('publication_failed')
        self.called = True
        cancel = cancel or (lambda: False)
        aborted = exit.cancelled or exit.timed_out

        def tick():
            if time.monotonic() >= deadline:
                raise error('timeout')
            source.check()

        # 이미 처리한 실행 취소를 다시 적용해 partial 검사를 즉시 중단하지 않는다.
        try:
            tick()
            inspection = inspect_capture_fd(source.fd,size=source.size,command=self.command,
                                             deadline=deadline,cancel=None,check=source.check)
        except PwehError as exc:
            if getattr(exc,'code',None) in ('sigrok_capture_bad_zip','sigrok_capture_empty'):
                return CapturePublication('invalid_output',None,None,source.size,None,False,
                                          'bad_zip' if exc.code.endswith('bad_zip') else 'empty_capture')
            raise public_error(exc) from None
        # sample_shortfall은 종료 원인이 아니라 측정된 결과 부족이다.
        shortfall = inspection.samples < self.command.samples
        self.precommit_cancelled = bool(cancel()) and not aborted
        partial = aborted or self.precommit_cancelled or shortfall
        if self.cli_failed or (exit.returncode != 0 and not aborted):
            return CapturePublication('invalid_output',None,None,source.size,None,False,'cli_failed')
        root_fd = dir_fd = dst_fd = -1
        try:
            root_fd = safeio.open_dir_chain(self.case.dir)
            root_id = _directory(os.fstat(root_fd))
            dir_fd = safeio.open_dir_chain(self.case.dir,['signals'],create=True)
            dir_id = _directory(os.fstat(dir_fd))

            def parents():
                if (_directory(os.stat(self.case.dir,follow_symlinks=False)) != root_id
                        or _directory(os.fstat(root_fd)) != root_id
                        or _directory(os.stat('signals',dir_fd=root_fd,follow_symlinks=False)) != dir_id
                        or _directory(os.fstat(dir_fd)) != dir_id):
                    raise error('check_failed')

            stem = self.output_name or 'capture-ols'
            if partial:
                stem += '-partial'
            def reserve(stem, explicit):
                for number in range(1,1001):
                    name = stem+'.sr' if number==1 else f'{stem}-{number:03d}.sr'
                    try:
                        fd = os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dir_fd)
                        return name,fd
                    except FileExistsError:
                        if explicit:
                            raise error('artifact_exists') from None
                raise error('artifact_exists')
            parents()
            name,dst_fd = reserve(stem,self.output_name is not None)
            self.path = 'signals/'+name
            def copying_check():
                tick(); parents()
                current=os.fstat(dst_fd)
                named=os.stat(name,dir_fd=dir_fd,follow_symlinks=False)
                if (not stat.S_ISREG(current.st_mode) or current.st_nlink!=1
                        or (named.st_dev,named.st_ino)!=(current.st_dev,current.st_ino)):
                    raise error('check_failed')
            digest=safeio.hash_fd(source.fd,source.size,algorithms=('sha256',),out_fd=dst_fd,check=copying_check)['sha256']
            os.fsync(dst_fd); os.fchmod(dst_fd,0o444)
            seal=_identity(os.fstat(dst_fd))
            if seal[5]!=source.size:
                raise error('check_failed')

            def destination():
                parents()
                if (_identity(os.fstat(dst_fd))!=seal
                        or _identity(os.stat(name,dir_fd=dir_fd,follow_symlinks=False))!=seal):
                    raise error('check_failed')

            def check(entry):
                tick(); destination()
                if (entry.get('path')!=self.path or entry.get('size')!=source.size
                        or entry.get('is_dir') is not False or entry.get('sha256')!=digest):
                    raise error('check_failed')
                # 복사 뒤 새 취소는 정상 commit으로 진행하지 않고 미게시 원본을 보존한다.
                if not aborted and not self.precommit_cancelled and cancel():
                    self.precommit_cancelled=True
                    raise error('cancelled')

            details=inspection.to_dict()
            status='cancelled' if exit.cancelled or self.precommit_cancelled else 'timeout' if exit.timed_out else 'partial' if shortfall else 'succeeded'
            requested=self.command.approval_identity()
            def committed(entry):
                self.artifact=dict(entry)
                self.result={'ok':not(aborted or self.precommit_cancelled),'status':status,
                    'backend':'windows','path':self.path,'artifact':self.artifact,'sha256':digest,
                    'size':source.size,'requested':requested,'bundle':self.bundle_meta,
                    'inspection':details,'partial':partial,'cleanup_pending':True,
                    'driver':'ols','conn':self.command.conn,'samplerate':inspection.samplerate_hz,
                    'samples':inspection.samples,'unitsize':inspection.unitsize,
                    'duration_s':round(inspection.samples/inspection.samplerate_hz,6),
                    'channels':[ch.name for ch in inspection.channels],
                    'activity':[dict(ch,high_ratio=(ch['high_count']/inspection.activity_samples
                        if inspection.activity_samples else None)) for ch in details['activity']],
                    'activity_complete':inspection.activity_complete,
                    'activity_samples':inspection.activity_samples,
                    'reason':('cancelled' if exit.cancelled or self.precommit_cancelled else 'timeout' if exit.timed_out
                              else 'sample_shortfall' if shortfall else None),
                    'warnings':list(inspection.notes),
                    'next_steps':'같은 케이스의 sigrok_file_info 또는 sigrok_estimate_baud로 저장된 캡처를 확인하세요.'}
                self.receipt=CapturePublication('published',self.path,entry['id'],source.size,digest,partial,
                    'cancelled' if exit.cancelled or self.precommit_cancelled else 'timeout' if exit.timed_out else 'sample_shortfall' if shortfall else None)
                source.on_commit(self.receipt)
                if self.job_context is not None:
                    self.job_context.set_partial(dict(self.result))
                    if not aborted and not self.precommit_cancelled:
                        self.job_context.mark_committed()
            self.case.register_artifact(self.path,kind='signal-capture',producer='sigrok-mcp',
                description='Windows OLS 유한 캡처'+(' (부분)' if partial else ''),
                sha256=digest,check=check,on_commit=committed,deadline=deadline,replace_existing=False,
                extra={'backend':'windows','requested':requested,'bundle':self.bundle_meta,
                       'samples_captured':inspection.samples,'samplerate':inspection.samplerate_hz,'partial':partial})
            destination(); source.check()
            return self.receipt
        except Exception as exc:
            # 생성된 final 이름은 commit 불확실성 때문에 포괄 삭제하지 않는다.
            raise public_error(exc) from None
        finally:
            for fd in (dst_fd,dir_fd,root_fd):
                if fd>=0:
                    os.close(fd)
