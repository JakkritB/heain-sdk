#!/usr/bin/env bash
# heain-sdk live test 3b: two SDK apps talking to each other through a real
# heain-core node.
#  - greeter-app serves formal and non-formal endpoints, an AI capability and
#    two unlinkable lanes; greeter-caller calls it with App.Call (uses[],
#    discovery, mTLS with the callee's identity checked);
#  - a formal call is audited in core exactly once, a non-formal call never;
#  - an AI answer carries a signed reasoning record stored in core's audit,
#    with no raw input, linked to the call's audit event; an AI answer
#    without its record is refused (reasoning_record_missing);
#  - lanes: missing lane header and a trace id crossing identity -> ballot
#    are refused (lane_violation); App.Call starts a fresh trace per lane;
#  - a dependency not in uses[] is refused before any network call.
# Needs ~/heain-core (its test harness builds the core node). ~1-2 min.
# Run from ~/heain-sdk:  bash scripts/live_3b.sh
set -uo pipefail
SDK=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/sdk-3b
URL=https://127.0.0.1:18000
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
inst() { as admin $URL/v1/admin/apps | python3 -c "
import json,sys
def walk(x):
    if isinstance(x,dict):
        if x.get('app_id')=='$1' and x.get('instance_id')=='$2': print(x.get('status')); sys.exit()
        for v in x.values(): walk(v)
    elif isinstance(x,list):
        for v in x: walk(v)
walk(json.load(sys.stdin))" 2>/dev/null; }
# aud <python expr over list E of audit events> -- E = [record['event'], ...]
aud() { as admin "$URL/v1/admin/audit?limit=2000" | python3 -c "
import json,sys
E=[r['event'] for r in json.load(sys.stdin)['records']]
def app(cap=None,res=None): return [e for e in E if e['Action']=='app.event' and (cap is None or e['Detail'].get('capability')==cap) and (res is None or e['Result']==res)]
print($1)" 2>/dev/null; }
line() { grep "^CALL $1 " "$W/caller.out" | head -1; }
approve() { local a; a=$(grep -o "action=[^ ]*" "$1" | head -1 | cut -d= -f2)
  [ -n "$a" ] && [ "$(code approver-1 -X POST $URL/v1/admin/policy/$a/approve)" = 200 ]; }

echo "== 0. core node G with provisioning; build the two example apps"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
( cd "$SDK" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/greeter" ./examples/greeter && \
  GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/greeter-caller" ./examples/greeter-caller ) && ok "example apps build" || { bad "SDK build"; exit 1; }
COMMON="-core $URL -core-id G -ca $C/ca.pem -chain $W/prov.pem"

echo "== 1. greeter-app: enroll, register, admitted by the Approver, serving"
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"greeter-app.g1"}' $URL/provision/token > "$W/tok-g.json"
"$W/greeter" $COMMON -manifest "$SDK/examples/greeter/heain-app.yaml" -instance g1 -app-id greeter-app \
  -cert "$W/g.pem" -key "$W/g.key" -enroll-token-json "$W/tok-g.json" -listen 127.0.0.1:19443 > "$W/greeter.out" 2>&1 &
GP=$!
for i in $(seq 1 20); do grep -q SERVING "$W/greeter.out" && break; sleep 1; done
approve "$W/greeter.out" && ok "greeter-app enrolled and admitted (P5 app.register)" || bad "greeter: $(cat "$W/greeter.out")"
for i in $(seq 1 15); do [ "$(inst greeter-app g1)" = active ] && break; sleep 1; done
[ "$(inst greeter-app g1)" = active ] && grep -q "SERVING 127.0.0.1:19443" "$W/greeter.out" && ok "greeter-app.g1 active, serving mTLS on 19443" || bad "greeter active: $(inst greeter-app g1)"

echo "== 2. greeter-caller calls greeter-app through App.Call"
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"greeter-caller.c1"}' $URL/provision/token > "$W/tok-c.json"
"$W/greeter-caller" $COMMON -manifest "$SDK/examples/greeter-caller/heain-app.yaml" -instance c1 -app-id greeter-caller \
  -cert "$W/c.pem" -key "$W/c.key" -enroll-token-json "$W/tok-c.json" > "$W/caller.out" 2>&1 &
CP=$!
for i in $(seq 1 20); do grep -q REGISTERED "$W/caller.out" && break; sleep 1; done
approve "$W/caller.out" || bad "caller approve: $(cat "$W/caller.out")"
for i in $(seq 1 40); do grep -q DONE "$W/caller.out" && break; sleep 1; done
wait $CP 2>/dev/null
grep -q DONE "$W/caller.out" || bad "caller did not finish: $(cat "$W/caller.out")"
line hello | grep -q 'status=200 .*"by":"greeter-caller.c1"' && ok "formal call answered; greeter saw the caller as greeter-caller.c1" || bad "hello: $(line hello)"
line hello-get | grep -q 'status=200' && ok "non-formal call answered" || bad "hello-get: $(line hello-get)"
[ "$(aud "len(app('greet.hello'))")" = 1 ] && ok "core audit: exactly 1 app.event for greet.hello (formal POST yes, non-formal GET no)" || bad "hello events: $(aud "len(app('greet.hello'))")"
[ "$(aud "app('greet.hello')[0]['Detail']['app_actor']")" = greeter-caller.c1 ] && [ "$(aud "app('greet.hello')[0]['Actor']")" = greeter-app.g1 ] \
  && ok "the event is written by greeter-app.g1 with actor greeter-caller.c1" || bad "event actor"
REC=$(line tone | grep -o '"record_id":"[^"]*"' | cut -d'"' -f4)
line tone | grep -q 'status=200 .*"tone":"loud"' && [ -n "$REC" ] && ok "AI call answered with reasoning record $REC" || bad "tone: $(line tone)"
[ "$(aud "sum(1 for e in E if e['Action']=='ai.reasoning_record' and e['Detail']['record_id']=='$REC')")" = 1 ] && ok "core stored the record in its audit" || bad "record not in core audit"
[ "$(aud "[e for e in E if e['Action']=='ai.reasoning_record'][0]['Detail']['trace_id']==app('greet.tone','ok')[0]['Detail']['trace_id'] and '$REC' in app('greet.tone','ok')[0]['Detail']['detail']['reasoning_record_ids']")" = True ] \
  && ok "record and call event share the trace id; the event lists the record id" || bad "record not linked"
as admin "$URL/v1/admin/audit?limit=2000" | grep -q "great news" && bad "raw AI input reached core" || ok "raw input never left the app (input is sha256 only)"
[ "$(aud "len([e for e in E if e['Action']=='ai.reasoning_record'][0]['Detail']['record'].get('signature',''))>40")" = True ] && ok "the record is signed (JCS + app key)" || bad "record unsigned"
line tone-unrecorded | grep -q 'status=500 code=reasoning_record_missing' && ok "an AI answer without its record is refused (reasoning_record_missing)" || bad "unrecorded: $(line tone-unrecorded)"
[ "$(aud "len(app('greet.tone','error:reasoning_record_missing'))")" = 1 ] && ok "the refusal is audited" || bad "unrecorded audit"
line id | grep -q 'status=200' && line ballot | grep -q 'status=200' && ok "App.Call: identity then ballot from one context both pass (fresh trace per lane)" || bad "lanes via Call: $(line id) / $(line ballot)"
[ "$(aud "len(set(e['Detail']['trace_id'] for e in app('greet.id','ok')) & set(e['Detail']['trace_id'] for e in app('greet.ballot','ok')))")" = 0 ] \
  && ok "no trace id appears in both lanes in core's audit" || bad "trace crossed lanes"
grep -q "CALL undeclared notdeclared=true" "$W/caller.out" && ok "a dependency not in uses[] is refused before any network call" || bad "uses[]"

echo "== 3. lanes and identity at the greeter's door (raw mTLS)"
raw() { curl -sk --cert "$W/c.pem" --key "$W/c.key" -o "$W/raw.out" -w "%{http_code}" -X POST "$@"; }
n0=$(aud "len(app(res='refused:lane_violation'))")
[ "$(raw https://127.0.0.1:19443/v1/id)" = 400 ] && grep -q lane_violation "$W/raw.out" && ok "no lane header -> 400 lane_violation" || bad "missing lane: $(cat "$W/raw.out")"
[ "$(raw -H 'X-Heain-Trace: t-cross-1' -H 'X-Heain-Lane: identity' https://127.0.0.1:19443/v1/id)" = 200 ] && \
[ "$(raw -H 'X-Heain-Trace: t-cross-1' -H 'X-Heain-Lane: ballot' https://127.0.0.1:19443/v1/ballot)" = 400 ] && grep -q unlinkable "$W/raw.out" \
  && ok "the same trace id in identity then ballot -> the ballot call is refused" || bad "crossing: $(cat "$W/raw.out")"
[ "$(aud "len(app(res='refused:lane_violation'))")" = $((n0+2)) ] && ok "both refusals are audited" || bad "lane refusal audit"
[ "$(aud "sum(1 for e in app('greet.ballot') if e['Detail']['trace_id']=='t-cross-1')")" = 0 ] && ok "the crossing trace id is not written into the ballot lane" || bad "crossing id linked"
c=$(curl -sk --cert "$C/admin.pem" --key "$C/admin.key" -o "$W/raw.out" -w "%{http_code}" -X POST -H 'X-Heain-Lane: identity' https://127.0.0.1:19443/v1/id)
[ "$c" = 403 ] && grep -q identity_mismatch "$W/raw.out" && ok "a non-app certificate is refused (403 identity_mismatch)" || bad "non-app cert: $c"
c=$(curl -sk -o /dev/null -w "%{http_code}" -X POST https://127.0.0.1:19443/v1/hello)
[ "$c" = 000 ] && ok "no client certificate -> TLS handshake refused" || bad "no cert: $c"
[ "$(raw https://127.0.0.1:19443/v1/undeclared)" = 404 ] && ok "an undeclared path is not served" || bad "undeclared path"

echo "== 4. leave"
kill -TERM $GP; wait $GP 2>/dev/null
grep -q DEREGISTERED "$W/greeter.out" && [ "$(inst greeter-app g1)" = deregistered ] && ok "greeter SIGTERM -> deregistered" || bad "greeter leave: $(inst greeter-app g1)"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"

echo "== cleanup"
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
