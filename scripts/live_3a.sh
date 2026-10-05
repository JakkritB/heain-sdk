#!/usr/bin/env bash
# heain-sdk live test 3a: the SDK against a real heain-core node.
#  - an app instance gets its certificate through the real provisioning flow
#    (token -> CSR -> probation -> confirm), never a pre-made certificate;
#  - starts from its manifest (YAML or JSON), registers, waits for the
#    Approver to admit the new app, keeps its registration alive, leaves;
#  - an invalid manifest is refused by the SDK before any call AND by core
#    (spec 05 C1); a certificate that does not match <app-id>.<instance-id>
#    is refused (C3).
# Needs ~/heain-core (its test harness builds the core node). ~1 min.
# Run from ~/heain-sdk:  bash scripts/live_3a.sh
set -uo pipefail
SDK=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/sdk-3a
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
        if x.get('app_id')=='hello-app' and x.get('instance_id')=='$1': print(x.get('status')); sys.exit()
        for v in x.values(): walk(v)
    elif isinstance(x,list):
        for v in x: walk(v)
walk(json.load(sys.stdin))" 2>/dev/null; }
ev() { as admin "$URL/v1/admin/audit?limit=1000" | j "sum(1 for x in d['records'] if x['event']['Action']=='$1')"; }

echo "== 0. core node G with provisioning; build the SDK example"
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
( cd "$SDK" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/hello" ./examples/hello ) && ok "SDK example builds" || { bad "SDK build"; exit 1; }
cp "$SDK/manifest/testdata/hello.yaml" "$SDK/manifest/testdata/hello.json" "$W/"
HELLO="$W/hello -core $URL -core-id G -ca $C/ca.pem -cert $W/app.pem -key $W/app.key"

echo "== 1. enroll through provisioning, start, wait for the Approver, leave"
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"hello-app.a1"}' $URL/provision/token > "$W/token.json"
$HELLO -manifest "$W/hello.yaml" -instance a1 -app-id hello-app -chain "$W/prov.pem" -enroll-token-json "$W/token.json" > "$W/run1.out" 2>&1 &
HP=$!
for i in $(seq 1 20); do grep -q REGISTERED "$W/run1.out" && break; sleep 1; done
grep -q "ENROLLED serial=" "$W/run1.out" && ok "certificate obtained through token -> CSR -> confirm" || bad "enroll: $(cat "$W/run1.out")"
openssl x509 -in "$W/app.pem" -noout -subject | grep -q "CN *= *hello-app.a1" && ok "certificate CN is hello-app.a1" || bad "cert CN"
AID=$(grep -o "action=[^ ]*" "$W/run1.out" | cut -d= -f2)
grep -q "REGISTERED status=pending_approval" "$W/run1.out" && [ -n "$AID" ] && ok "a new app waits for the Approver (P5 app.register $AID)" || bad "register: $(cat "$W/run1.out")"
[ "$(code approver-1 -X POST $URL/v1/admin/policy/$AID/approve)" = 200 ] && ok "Approver admitted hello-app 1.0.0" || bad "approve"
for i in $(seq 1 15); do grep -q ACTIVE "$W/run1.out" && break; sleep 1; done
grep -q ACTIVE "$W/run1.out" && [ "$(inst a1)" = active ] && ok "the SDK saw the admission; core lists hello-app.a1 active" || bad "active: $(inst a1) / $(tail -2 "$W/run1.out")"
sleep 12
[ "$(inst a1)" = active ] && ok "heartbeats keep it live past the 30 s TTL window start" || bad "not kept alive: $(inst a1)"
kill -TERM $HP; wait $HP 2>/dev/null
grep -q DEREGISTERED "$W/run1.out" && [ "$(inst a1)" = deregistered ] && ok "SIGTERM -> graceful deregister" || bad "deregister: $(inst a1)"
[ "$(ev app.registered)" -ge 1 ] && [ "$(ev app.deregistered)" -ge 1 ] && ok "core audited app.registered and app.deregistered" || bad "audit"

echo "== 2. the same app from its JSON manifest"
$HELLO -manifest "$W/hello.json" -instance a1 -wait-active 10s > "$W/run2.out" 2>&1 &
HP=$!; for i in $(seq 1 10); do grep -q ACTIVE "$W/run2.out" && break; sleep 1; done
grep -q ACTIVE "$W/run2.out" && ok "JSON manifest: registered and active at once (version already admitted)" || bad "json: $(cat "$W/run2.out")"
kill -TERM $HP; wait $HP 2>/dev/null

echo "== 3. refusals"
n0=$(ev app.registered)
sed '0,/^    formal: true$/{//d}' "$W/hello.yaml" > "$W/noformal.yaml"
grep -c "formal: true" "$W/noformal.yaml" >/dev/null
timeout 20 $HELLO -manifest "$W/noformal.yaml" -instance a1 > "$W/run3.out" 2>&1
grep -q "REFUSED stage=start.*manifest_formal_missing" "$W/run3.out" && [ "$(ev app.registered)" = "$n0" ] && ok "SDK refuses to start without formal, before calling core" || bad "sdk formal: $(cat "$W/run3.out")"
python3 - "$W" <<'PY'
import json,sys
w=sys.argv[1]; m=json.load(open(w+"/hello.json")); del m["capabilities"][0]["formal"]
open(w+"/noformal.req","w").write(json.dumps({"manifest":m,"instance_id":"a1"}))
PY
r=$(curl -sk --cert "$W/app.pem" --key "$W/app.key" --cacert "$C/ca.pem" -X POST -d @"$W/noformal.req" $URL/v1/app/register)
[ "$(echo "$r" | j "d['error']['code']")" = manifest_formal_missing ] && ok "core refuses the same manifest too (C1: both sides)" || bad "core formal: $r"
timeout 20 $HELLO -manifest "$W/hello.yaml" -instance a2 > "$W/run4.out" 2>&1
grep -q "REFUSED stage=start.*identity_mismatch" "$W/run4.out" && ok "certificate for a1 cannot start instance a2 (identity_mismatch)" || bad "identity: $(cat "$W/run4.out")"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"

echo "== cleanup"
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
