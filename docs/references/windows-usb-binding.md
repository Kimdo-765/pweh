# Windows USB 관찰 범위 코어

`pweh.usb_binding`은 호출자가 제공한 두 Windows Present graph에서 지정 VID/PID의 유일한 USB 부모와 전체 하위 장치·COM 별명을 선택하는 순수 코어다. 기존 직렬 포트의 whole-device scope와 같은 잠금 키를 반환한다. **공개 USB 실행 프로필이나 새 MCP 도구를 추가하지 않는다.**

입력은 `portidentity.PS_USB_SCOPE`의 `pweh.pnp-usb-scope/v1` 형식이다. 코어는 해당 PowerShell script를 실행하지 않으며 환경 감지·포트 열기·USB control 요청·드라이버 설치도 하지 않는다. 호출자가 이미 얻은 관찰 bytes를 검증하는 API다. [Windows OpenOCD dummy](windows-openocd-dummy.md)의 무USB·무초기화 범위와 기존 Linux/직렬 포트 경로는 유지된다.

## 1. API와 불변 결과

```python
parse_windows_usb_scope(raw: bytes, *, vid: str, pid: str,
                        deadline: float, cancel=None) -> WindowsUsbScope
revalidate_windows_usb_scope(previous: WindowsUsbScope, raw: bytes, *,
                             deadline: float, cancel=None) -> WindowsUsbScope
```

`raw`는 정확한 `bytes`형이며 `vid`와 `pid`는 각각 정확한 4자리 16진 문자열이다. 성공한 `WindowsUsbScope`의 두 값은 소문자로 정규화된다. `deadline`은 monotonic 시계의 절대 종료 시각이며 입력 검증·graph 순회·선택·fresh 대조에 같은 예산을 적용한다. `cancel`은 `bool`을 반환하는 선택적 취소 확인 콜백이며, 예외나 다른 반환형은 미확인 실패다.

| 필드 | 의미 |
|---|---|
| `backend`, `selector_kind` | 고정값 `windows`, `vid-pid` |
| `vid`, `pid` | 선택한 한 쌍의 VID/PID |
| `usb_parent` | 선택된 non-MI USB 부모의 정규화된 PnP instance ID |
| `whole_device` | 고정값 `True`; 임의 interface 부분집합을 뜻하지 않음 |
| `claim_keys` | 정렬된 전체 잠금 키 tuple |
| `com_aliases` | 정렬된 `(COMn, instance_id)` tuple의 tuple |
| `binding_nodes` | 정렬된 `(instance_id, parent, parent_state, COMn 또는 None, pnp_class)` tuple의 tuple |
| `provider_basis` | 고정값 `pweh.pnp-usb-scope/v1` |

결과는 frozen 값이며 가변 graph나 관찰 시각을 보관하지 않는다. PnP instance tail을 USB descriptor serial로 바꾸지 않고, 실제 CLI profile이나 선택 interface를 결과에 넣지 않는다. 호출자가 값을 구성했다는 사실만으로 관찰의 신뢰나 실행 허가가 생기지 않는다.

## 2. 완전성·유일성·상한

각 snapshot은 `present_count`, `nodes`, `errors`를 가진다. node는 `instance_id`, `parent`, `parent_state`, `com`, `pnp_class`를 가진다. 두 전체 graph의 개수·오류·중복·부모 연결과 동등성을 먼저 확인한다. 배열 순서가 다르더라도 정규화된 graph가 같으면 같은 관찰이다. `HTREE\ROOT\0` 종결 규칙은 기존 COM scope와 같다.

선택은 전체 graph에서 지정 VID/PID에 해당하는 물리 USB 부모가 정확 하나일 때만 성공한다. canonical `USB\VID_....&PID_....&MI_..\...` interface를 별도 물리 후보로 중복 세지 않는다. 같은 VID/PID를 포함하나 해석할 수 없는 node를 버려 유일성을 만들지 않는다. 부모가 같다는 근거가 있는 모든 하위 장치를 포함하며 COM 별명이 없는 USB 부모도 선택할 수 있다. COM의 전역 중복, 해석할 수 없는 직렬 별명이나 불완전 graph는 성공 범위를 축소하는 대신 실패한다.

| 한도 | 값 |
|---|---:|
| 입력 bytes | 1 MiB |
| 호출의 관찰 해석 예산 | 최대5초, caller deadline 이내 |
| snapshot당 node | 8192개 |
| 부모 연결 깊이 | 16 |
| 선택 subtree | 256개 node |
| 전체 잠금 키 | 64개 |

오류는 `usb_scope_invalid`, `usb_scope_unknown`, `usb_scope_absent`, `usb_scope_ambiguous`, `usb_scope_changed`, `usb_scope_cancelled`, `usb_scope_timeout`의 고정 code로 구분한다. raw JSON, PnP ID, 경로 또는 내부 예외 원문을 오류에 붙이지 않는다. 취소 콜백 자체의 무한 블로킹을 선점 종료하는 API는 아니므로 호출자는 짧은 내부 콜백만 전달해야 한다.

## 3. 기존 COM 잠금과의 호환

전체 scope의 키는 하위 node마다 `winif:<정규화된 PnP instance ID>`, COM 별명마다 `win:COMn`이다. 별도의 USB serial 잠금 namespace를 만들지 않는다. 같은 raw에서 선택한 COM에 대해 `portidentity.parse_windows_scope(route, raw)`가 반환하는 `.keys`는 새 USB scope의 `.claim_keys`와 같다.

기존 `PortLockManager.acquire(scope.claim_keys, owner=...)`를 사용하면 같은 부모의 UART·ESP·OLS COM lease와 충돌한다. COM이 없는 interface도 `winif:` 키로 잠긴다. 키는 정렬하여 모두 취득하거나 모두 rollback하며, 다른 부모의 COM lease는 독립적이다. **whole-device 선택을 FTDI 채널별 동시 사용 허용으로 해석하지 않는다.** 운영 manager의 namespace/runtime 위치는 기존 규칙을 유지하고, 시험만 명시한 합성 namespace와 임시 runtime root를 사용한다.

`revalidate_windows_usb_scope`는 새 두 graph를 검증한 뒤 선택 부모·하위 장치·COM 별명·키가 이전 값과 같은지 대조한다. 후보의 부재·복수·미확인과 결속 변화는 `usb_scope_changed`이며 시간 초과·취소는 각각의 code를 유지한다. 새 같은 VID/PID 부모, sibling 또는 별명이 생기면 계속 사용할 범위를 자동 확대하지 않는다. 이 함수는 lease를 취득·교체·해제하지 않으므로 실패해도 이미 취득한 lease는 caller가 명시적으로 정리할 때까지 유지된다.

## 4. 결과가 증명하지 않는 것

complete graph는 제한된 OS 관찰의 완결성이다. 실제 OpenOCD/libusb의 후보 선택·claim 성공, 드라이버 설치 상태, reset의 전기적 영향, 외부 프로그램의 배타, 관찰 뒤 hotplug 원자성 또는 대상 기기의 소유·허가를 증명하지 않는다. PWEH lease도 이를 대신하지 않는다.

이 코어는 role store나 instrument guard를 호출하거나 허용 기준을 바꾸지 않는다. 향후 USB 실행 소비자는 전체 별명의 역할 확인, active instrument pin 검사, 분류·승인 지문, spawn 직전 fresh 대조와 실제 child 종료 확인까지 별도로 연결해야 한다. pin0의 빠른 반환과 active pin의 미확인 거부를 PnP tail로 우회하지 않는다. 실제 모델·배선의 확인은 실기 사용에 필요하며, 순수 코어와 합성 통합시험의 완료 조건과 구분한다.

## 5. 합성 검증 범위

`tests/core/test_usb_binding.py`는 입력·유일성·완전성·fresh·상한을 검사한다. `tests/core/test_usb_binding_integration.py`는 독립 canonical graph로 기존 COM wrapper와의 exact-key 일치, 서로 다른 임시 runtime의 같은 namespace 잠금 충돌, 바깥 부모의 독립성, 마지막 키 충돌의 전체 rollback, fresh 실패 중 기존 lease 보존과 COM 없는 scope를 확인한다. 실제 Windows/PnP/USB 장치를 조회하지 않는다.
