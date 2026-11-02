"""Ultralight 계열 CU snapshot(UT- inventory)의 소유 증명 결속 오프라인 분석.

NTAG 분석(``analysis``)의 입력 FD·디렉터리 봉인·원장 조회 도구를 읽기 전용으로 쓰고 결과는 별도 schema
(``nfc-ul-file-analysis``)·별도 이름(``analysis/nfc-ul-file-NNN.json``·``nfc-ul-diff-NNN.json``)으로 저장한다.

입구 규칙:
  - 받는 파일은 서버가 만든 ``nfc/cu-ul-read-NNN.json``(등록 type ``nfc-cu-ul-snapshot``, 0444)뿐이다. 가져온 v4·NTAG
    snapshot은 ``nfc_source_mismatch``다. ISO 헤더 파일의 file identity 대조 경로는 없다.
  - 같은 경로의 최신 원장 행은 ``nfc-mcp/nfc_cu_read_start``의 device-read이고 attestation_id가 snapshot의 증명 id와 같아야 한다.
    크기·SHA·원장 extra 전체·snapshot binding·scan identity가 현재 UL inventory와 같아야 한다.
  - 사람 소유 증명(tag-ownership)은 입구 뒤 호출자가 ctx 없이 다시 확인하고(없으면 attestation_required), 분석 단계와
    등록 check에서 같은 id를 동기 재확인한다. 철회·만료되면 기존 snapshot도 다시 증명할 때까지 분석하지 않는다.
결과에는 원시 UID·페이지 값을 넣지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass

from pweh import cu_protocol, nfc_cu_ul_snapshot as UN, nfc_ul_inventory as UL, safeio, schemas
from pweh.safety.attestations import canonical_json

from . import analysis as A

SOURCE = {'server': 'nfc-mcp', 'tool': 'nfc_cu_read_start'}
OUTPUT_TYPE = 'nfc-ul-file-analysis'
_UT = re.compile(r'UT-[0-9a-f]{32}')
_ATT = re.compile(r'att-[0-9a-f]{10}')
_error = A._error


@dataclass(frozen=True, repr=False)
class UlAdmission:
    """사람 증명을 기다리는 동안 원문·경로·FD를 보유하지 않는 결속."""
    artifacts: tuple
    binding: tuple
    family: str
    ul_identity_digest: str


def _arguments(artifact_ids, tag_ref, deadline, cancel):
    try:
        finite = type(deadline) in (int, float) and math.isfinite(deadline)
    except OverflowError:
        finite = False
    if (type(artifact_ids) is not tuple or len(artifact_ids) not in (1, 2)
            or any(type(x) is not str or re.fullmatch(r'A-[0-9]{4,8}', x) is None for x in artifact_ids)
            or type(tag_ref) is not str or _UT.fullmatch(tag_ref) is None
            or not finite or cancel is not None and not callable(cancel)):
        raise _error('nfc_input_invalid')


def _binding(bound):
    return (bound.tag_ref, bound.scan_ref, bound.ul_identity_digest, bound.scan_seq, bound.scan_entry_sha256,
            bound.inventory_seq, bound.inventory_entry_sha256, bound.family)


def _entry_sha(entry):
    return hashlib.sha256(canonical_json(entry).encode('utf-8')).hexdigest()


def _cu_ul_sources(runtime, case, inputs, bound, entries, deadline, cancel):
    """최신 동일 경로 행을 먼저 선택하고 Ultralight 전용 출처·증명 id·snapshot 결속을 검사한다."""
    from pweh.nfc_inventory import _reader_binding
    UL.check_ul_inventory_entries(runtime, case, bound, entries, check=lambda: A._tick(deadline, cancel))
    binding = UN.binding_of(bound)
    identity = bound.identity
    snapshots, files = [], []
    for item in inputs.rows:
        A._tick(deadline, cancel)
        row = item['row']
        rec = next((e for e in reversed(entries) if e.get('path') == row['path']), None)
        if (rec is None or rec.get('kind') != 'device-read' or not A._exact(rec.get('source'), SOURCE)
                or type(rec.get('attestation_id')) is not str or _ATT.fullmatch(rec['attestation_id']) is None
                or not A._exact(rec.get('size'), row['size']) or rec.get('sha256') != row['sha256']
                or type(rec.get('seq')) is not int or not 1 <= rec['seq'] <= (1 << 63) - 1):
            raise _error('nfc_source_mismatch')
        snapshot = UN.parse_cu_ul_snapshot(item['data'], deadline=deadline, cancel=cancel)
        if (snapshot.attestation_id != rec['attestation_id'] or not A._exact(dict(snapshot.binding), binding)
                or snapshot.family != bound.family
                or (snapshot.uid, snapshot.atqa_msb, snapshot.sak, snapshot.version)
                != (identity.uid, identity.atqa_msb, identity.sak, identity.version)):
            raise _error('nfc_source_mismatch')
        extra = rec.get('extra')
        # 원장 extra는 이 파일이 선언한 UL reader 행 전체와 같아야 한다. live 상수로 대신하지 않는다.
        reader = cu_protocol.known_ul_profile(snapshot.reader_profile)
        if reader is None:
            raise _error('nfc_source_mismatch')
        expected = {'snapshot_profile': UN.SNAPSHOT_PROFILE, 'reader_profile': reader.profile,
                    'reader_profile_sha256': reader.profile_sha256, 'firmware_commit': reader.firmware_commit,
                    'session_id': extra.get('session_id') if type(extra) is dict else None,
                    'reader_binding': extra.get('reader_binding') if type(extra) is dict else None,
                    'binding': binding, 'family': snapshot.family, 'pages_total': snapshot.pages_total,
                    'read_last_target': snapshot.read_last_target, 'pages_observed': snapshot.pages_observed,
                    'read_complete': snapshot.read_complete, 'stop_reason': snapshot.stop_reason,
                    'read_end': {'kind': snapshot.read_end[0], 'page': snapshot.read_end[1]},
                    'observed_variant': snapshot.observed_variant}
        session = expected['session_id']
        if (not A._exact(extra, expected) or type(session) is not str or not 1 <= len(session) <= 128
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in session)):
            raise _error('nfc_source_mismatch')
        _reader_binding(expected['reader_binding'])
        snapshots.append(snapshot)
        files.append({'artifact_id': row['id'], 'size': row['size'], 'sha256': row['sha256'],
                      'provenance_kind': 'device-read', 'ledger_seq': rec['seq'],
                      'ledger_entry_sha256': _entry_sha(rec), 'read_attestation_id': rec['attestation_id']})
    # 서로 다른 UL reader 프로필의 snapshot은 같은 inventory여도 비교하지 않는다.
    if len({snapshot.reader_profile for snapshot in snapshots}) > 1:
        raise _error('nfc_source_mismatch')
    return snapshots, files


def _ul_mode(inputs):
    if A._mode(inputs.rows) != 'cu-ul-snapshot':
        raise _error('nfc_source_mismatch')


def prepare_ul_admission(runtime, case, artifact_ids, tag_ref, *, deadline, cancel=None):
    """입구만 수행한다. 반환 전에 입력 FD를 모두 닫는다. 사람 증명은 호출자가 이 뒤에 확인한다."""
    inputs = failure = result = None
    try:
        _arguments(artifact_ids, tag_ref, deadline, cancel)
        A._tick(deadline, cancel)
        bound = UL.resolve_ul_inventory(runtime, case, tag_ref, deadline=deadline, cancel=cancel)
        inputs = A._Inputs(case, artifact_ids, deadline, cancel)
        _ul_mode(inputs)
        _cu_ul_sources(runtime, case, inputs, bound, A._entries(runtime, case, deadline, cancel), deadline, cancel)
        inputs.check(deadline, cancel, rehash=True)
        artifacts = tuple((i['row']['id'], i['row']['sha256']) for i in inputs.rows)
        result = UlAdmission(artifacts, _binding(bound), bound.family, bound.ul_identity_digest)
    except Exception as exc:
        failure = A._fixed(exc)
    finally:
        if inputs is not None and not inputs.close():
            failure = _error('nfc_cleanup_pending')
    if failure:
        raise failure from None
    return result


def _validate_ul_relations(report, snapshots):
    """JSON Schema가 구분하지 않는 exact 정수와 관찰·보류·비교 등식을 저장 직전에 대조한다."""
    def require(value):
        if not value:
            raise _error('nfc_failed')

    def numbers(value):
        if type(value) is dict:
            for child in value.values():
                numbers(child)
        elif type(value) is list:
            for child in value:
                numbers(child)
        elif type(value) is float:
            raise _error('nfc_failed')

    inspection = report['inspection']
    numbers(inspection)
    require(type(inspection['schema_version']) is int and inspection['schema_version'] == 1)
    require(report['operation'] == inspection['operation'] and report['status'] == inspection['status'])
    require(report['params']['profile'] == inspection['profile'] == UN.ANALYSIS_PROFILE)
    require(inspection['limitations'] == list(UN.LIMITATIONS))
    cov, summary = inspection['coverage'], inspection['summary']
    require(cov['input_bytes'] == cov['consumed_bytes'] == sum(s.input_size for s in snapshots))
    require(cov['unexamined_bytes'] == 0)
    require(len(report['source']['files']) == len(snapshots))
    for src, snapshot in zip(report['source']['files'], snapshots):
        require(type(src['size']) is int and src['size'] == snapshot.input_size
                and src['read_attestation_id'] == snapshot.attestation_id)
    first = snapshots[0]
    targets = first.read_last_target + 1
    withheld = first.pages_total - targets
    require(summary['family'] == first.family and summary['pages_total'] == first.pages_total
            and summary['read_last_target'] == first.read_last_target)

    def read_summary(snapshot):
        return {'pages_observed': snapshot.pages_observed,
                'read_end': {'kind': snapshot.read_end[0], 'page': snapshot.read_end[1]},
                'read_complete': snapshot.read_complete, 'stop_reason': snapshot.stop_reason,
                'observed_variant': snapshot.observed_variant}

    read_partial = any(not s.read_complete for s in snapshots)
    if inspection['operation'] == 'inspect':
        require(len(snapshots) == 1 and cov['input_exhausted'] is True)
        require(A._exact({k: summary[k] for k in ('pages_observed', 'read_end', 'read_complete', 'stop_reason',
                                                    'observed_variant')}, read_summary(first)))
        require(summary['withheld_pages_count'] == withheld == cov['pages_withheld'])
        require(summary['unobserved_fields'] == list(UN.UNOBSERVED_FIELDS))
        require(cov['pages_unobserved'] == targets - first.pages_observed)
        expected_reasons = ['read_partial'] if read_partial else []
        partial = read_partial
    else:
        require(len(snapshots) == 2)
        before, after = snapshots
        require(A._exact(summary['before'], read_summary(before)) and A._exact(summary['after'], read_summary(after)))
        counts = ('pages_compared', 'before_only_pages', 'after_only_pages', 'neither_observed_pages',
                  'withheld_pages', 'comparison_unexamined_pages')
        require(all(type(summary[k]) is int and summary[k] >= 0 for k in counts))
        require(sum(summary[k] for k in counts) == first.pages_total)
        require(summary['withheld_pages'] == withheld)
        processed = targets - summary['comparison_unexamined_pages']
        kb, ka = before.pages_observed, after.pages_observed
        require(summary['pages_compared'] == min(processed, kb, ka))
        require(summary['before_only_pages'] == max(0, min(processed, kb) - ka))
        require(summary['after_only_pages'] == max(0, min(processed, ka) - kb))
        require(summary['neither_observed_pages'] == max(0, processed - max(kb, ka)))
        changes = summary['changed_pages']
        require(all(type(p) is int and 0 <= p < summary['pages_compared'] for p in changes)
                and changes == sorted(set(changes)))
        complete = summary['comparison_unexamined_pages'] == 0
        require(cov['comparison_complete'] is complete and cov['changes_complete'] is complete
                and cov['changed_pages_count_is_lower_bound'] is (not complete))
        end_changed = before.read_end != after.read_end
        require(summary['read_end_changed'] is end_changed)
        equal = (not changes) if complete and not read_partial and not end_changed else None
        require(summary['stored_pages_equal'] is equal)
        expected_reasons = (['read_partial'] if read_partial else []) + ([] if complete else ['time_limit'])
        partial = read_partial or not complete
    require(cov['reasons'] == expected_reasons)
    require(inspection['status'] == ('partial' if partial else 'ok'))


def analyze_ul_files(runtime, case, artifact_ids, tag_ref, admission, attestation_id, *, max_seconds=5, cancel=None):
    """증명 확인 뒤 새 FD로 재선택하고 같은 증명 id·출처·같은 FD를 등록 commit까지 확인한다."""
    inputs = None
    output_fd = output_parent = output_name = output_identity = None
    committed = failure = report = None
    warnings = []
    output_path = output_hash = output_size = None
    try:
        if (type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5 or type(admission) is not UlAdmission
                or type(attestation_id) is not str or _ATT.fullmatch(attestation_id) is None
                or type(admission.artifacts) is not tuple or len(admission.artifacts) != len(artifact_ids)
                or any(type(p) is not tuple or len(p) != 2 or any(type(v) is not str for v in p)
                       for p in admission.artifacts)):
            raise _error('nfc_input_invalid')
        deadline = time.monotonic() + max_seconds
        _arguments(artifact_ids, tag_ref, deadline, cancel)
        A._tick(deadline, cancel)
        bound = UL.resolve_ul_inventory(runtime, case, tag_ref, deadline=deadline, cancel=cancel)
        if not A._exact(_binding(bound), admission.binding):
            raise _error('nfc_input_changed')
        UL.ul_require(runtime, case.id, bound.family, bound.ul_identity_digest, expected_id=attestation_id)
        inputs = A._Inputs(case, artifact_ids, deadline, cancel)
        if tuple((i['row']['id'], i['row']['sha256']) for i in inputs.rows) != admission.artifacts:
            raise _error('nfc_input_changed')
        _ul_mode(inputs)
        snapshots, files = _cu_ul_sources(runtime, case, inputs, bound, A._entries(runtime, case, deadline, cancel),
                                          deadline, cancel)
        inspection = (UN.inspect_cu_ul_snapshot(snapshots[0], deadline=deadline, cancel=cancel) if len(snapshots) == 1
                      else UN.diff_cu_ul_snapshots(*snapshots, deadline=deadline, cancel=cancel))
        final_end = time.monotonic() + A.FINAL_SECONDS
        report = {'schema': UN.REPORT_SCHEMA, 'operation': inspection['operation'], 'status': inspection['status'],
                  'source': {'kind': 'case-artifact', 'tag_ref': tag_ref, 'scan_ref': bound.scan_ref,
                             'scan_entry_sha256': bound.scan_entry_sha256,
                             'inventory_entry_sha256': bound.inventory_entry_sha256,
                             'tag_ownership_attestation_id': attestation_id, 'files': files},
                  'params': {'profile': UN.ANALYSIS_PROFILE, 'max_seconds': max_seconds},
                  'inspection': inspection, 'inventory_binding_verified': True, 'physical_same_tag_verified': False}
        schemas.validate('nfc-ul-file-analysis', report)
        _validate_ul_relations(report, snapshots)
        encoded = json.dumps(report, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(encoded) > A.MAX_OUTPUT_BYTES:
            raise _error('nfc_failed')
        output_size, output_hash = len(encoded), hashlib.sha256(encoded).hexdigest()
        output_parent = inputs.dirs.descend(['analysis'], final_end, cancel)
        prefix = 'nfc-ul-file' if len(snapshots) == 1 else 'nfc-ul-diff'
        for seq in range(1, 10001):
            A._tick(final_end, cancel)
            name = f'{prefix}-{seq:03d}.json'
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=output_parent)
            except FileExistsError:
                continue
            output_fd, output_name = fd, name
            output_identity = os.fstat(fd)
            output_path = 'analysis/' + name
            break
        if output_fd is None:
            raise _error('nfc_failed')
        pos = 0
        while pos < len(encoded):
            A._tick(final_end, cancel)
            n = os.write(output_fd, encoded[pos:pos + A.CHUNK])
            if n <= 0:
                raise _error('nfc_failed')
            pos += n
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
        output_seal = A._file_seal(os.fstat(output_fd))

        def check(entry):
            inputs.check(final_end, cancel, rehash=True)
            current = UL.resolve_ul_inventory(runtime, case, tag_ref, deadline=final_end, cancel=cancel)
            if not A._exact(_binding(current), admission.binding):
                raise _error('nfc_input_changed')
            UL.ul_require(runtime, case.id, current.family, current.ul_identity_digest, expected_id=attestation_id)
            _ul_mode(inputs)
            _, current_files = _cu_ul_sources(runtime, case, inputs, current, A._entries(runtime, case, final_end, cancel),
                                              final_end, cancel)
            if not A._exact(current_files, files):
                raise _error('nfc_source_mismatch')
            A._check_file(output_fd, output_parent, output_name, output_seal)
            if A._read_fd(output_fd, output_size, final_end, cancel)[0] != output_hash:
                raise _error('nfc_input_changed')
            if any(type(entry.get(k)) is not type(v) or entry.get(k) != v for k, v in
                   (('path', output_path), ('size', output_size), ('sha256', output_hash), ('is_dir', False))):
                raise _error('nfc_input_changed')
            inputs.check(final_end, cancel)
            A._check_file(output_fd, output_parent, output_name, output_seal)

        def on_commit(entry):
            nonlocal committed
            committed = dict(entry)

        case.register_artifact(output_path, kind='other', producer='pweh-nfc', extra={'type': OUTPUT_TYPE},
                               sha256=output_hash, check=check, on_commit=on_commit, deadline=final_end,
                               replace_existing=False)
        if committed is None:
            raise _error('nfc_failed')
    except Exception as exc:
        if committed is not None:
            warnings.append('post_commit_callback_failed')
        else:
            failure = A._fixed(exc)
    finally:
        if committed is None and output_fd is not None:
            try:
                inputs.dirs.check(float('inf'), None)
                named = os.stat(output_name, dir_fd=output_parent, follow_symlinks=False)
                if not safeio.same_file(named, output_identity) or not safeio.same_file(os.fstat(output_fd), output_identity):
                    raise _error('nfc_cleanup_pending')
                os.unlink(output_name, dir_fd=output_parent)
            except Exception:
                failure = _error('nfc_cleanup_pending')
        close_ok = True
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError:
                close_ok = False
        if inputs is not None:
            close_ok = inputs.close() and close_ok
        if not close_ok:
            if committed is not None:
                warnings.append('output_close_unconfirmed')
            else:
                failure = _error('nfc_cleanup_pending')
    if failure is not None:
        raise failure from None
    return {'ok': True, 'report': report,
            'analysis': {'path': output_path, 'sha256': output_hash, 'size': output_size,
                         'artifact_id': committed['id']}, 'warnings': warnings}
