#!/usr/bin/env bash
# heain-sdk live test 3d: the SDK against heain-core 1.3 after Step 3d.
#  - core reports 1.3.0;
#  - a job of the legacy /ingest path, run by P3 /execute, reaches an SDK
#    Worker through the generic App API executor (no LEGACY executor left);
#  - an app's server refuses a caller whose certificate core has revoked
#    (GET /v1/app/certs/{serial}), within the 10 s status cache.
# Needs ~/heain-core (its test harness builds the core node). ~2 min.
# Run from ~/heain-sdk:  bash scripts/live_3d.sh
set -uo pipefail
SDK=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/sdk-3d
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
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.tok"; }
approve() { local a; for i in $(seq 1 20); do grep -q REGISTERED "$1" && break; sleep 1; done
  a=$(grep -o "action=[^ ]*" "$1" | head -1 | cut -d= -f2)
  [ -z "$a" ] || [ "$(code approver-1 -X POST $URL/v1/admin/policy/$a/approve)" = 200 ]; }
COMMON="-core $URL -core-id G -ca $C/ca.pem -chain $W/prov.pem"
capp() { curl -sk --cert "$W/c.pem" --key "$W/c.key" "$@"; }

echo "== 0. core node G (P1-P5, provisioning); build the examples"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -ingest-queue-path="$T/data-G/queue.db" -approval-store-path="$T/data-G/approvals.db" \
  -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
( cd "$SDK" && for x in greeter greeter-caller worker; do GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/$x" ./examples/$x || exit 1; done ) && ok "examples build" || { bad "SDK build"; exit 1; }

echo "== 1. three apps against core 1.3"
token greeter-app.g1; token greeter-caller.c1; token worker-app.k1
"$W/greeter" $COMMON -manifest "$SDK/examples/greeter/heain-app.yaml" -instance g1 -app-id greeter-app \
  -cert "$W/g.pem" -key "$W/g.key" -enroll-token-json "$W/greeter-app.g1.tok" -listen 127.0.0.1:19443 > "$W/greeter.out" 2>&1 &
GP=$!; approve "$W/greeter.out" || bad "greeter approve"
"$W/worker" $COMMON -manifest "$SDK/examples/worker/heain-app.yaml" -instance k1 -app-id worker-app \
  -cert "$W/k.pem" -key "$W/k.key" -enroll-token-json "$W/worker-app.k1.tok" > "$W/worker.out" 2>&1 &
WP=$!; approve "$W/worker.out" || bad "worker approve"
for i in $(seq 1 20); do grep -q WORKING "$W/worker.out" && break; sleep 1; done
grep -q "registered with core G (1.3.0)" "$W/greeter.out" && ok "core reports version 1.3.0" || bad "version: $(grep registered "$W/greeter.out")"
"$W/greeter-caller" $COMMON -manifest "$SDK/examples/greeter-caller/heain-app.yaml" -instance c1 -app-id greeter-caller \
  -cert "$W/c.pem" -key "$W/c.key" -enroll-token-json "$W/greeter-caller.c1.tok" > "$W/caller.out" 2>&1 &
CP=$!; approve "$W/caller.out" || bad "caller approve"
for i in $(seq 1 40); do grep -q DONE "$W/caller.out" && break; sleep 1; done; wait $CP 2>/dev/null
grep -q "^CALL hello status=200" "$W/caller.out" && grep -q "^CALL tone status=200" "$W/caller.out" && ok "app-to-app calls pass with both certificates checked against core" || bad "calls: $(cat "$W/caller.out")"

echo "== 2. a legacy /ingest job runs in the SDK Worker (generic App API executor)"
TK=$(capp -X POST -H 'Content-Type: application/json' -d "{\"origin_zone\":\"zone-a\",\"category\":\"text.upper\",\"payload\":\"$(printf legacy-job | base64 -w0)\",\"classification\":{\"delivery\":\"IMMEDIATE\"}}" $URL/ingest | j "d['ticket_id']")
r=$(capp -X POST -H 'Content-Type: application/json' -d "{\"ticket_id\":\"$TK\"}" $URL/execute)
[ "$(echo "$r" | j "d['output_base64']" | base64 -d 2>/dev/null)" = LEGACY-JOB ] && grep -q "RAN $TK text.upper" "$W/worker.out" && ok "P3 /execute -> worker-app.k1 (SDK Worker) -> LEGACY-JOB" || bad "bridge: $r / $(tail -3 "$W/worker.out")"
[ "$(as admin "$URL/v1/admin/audit?limit=2000" | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Actor']=='worker-app.k1' and (x['event']['Detail'].get('detail') or {}).get('ticket_id')=='$TK')")" = 1 ] \
  && ok "the SDK audited the run once (formal text.upper)" || bad "worker audit"

echo "== 3. a revoked caller is refused by the app"
SER=$(openssl x509 -in "$W/c.pem" -noout -serial | cut -d= -f2 | python3 -c "import sys;print(int(sys.stdin.read().strip(),16))")
c=$(capp -o /dev/null -w "%{http_code}" -X POST https://127.0.0.1:19443/v1/hello)
[ "$c" = 200 ] && ok "before revocation: greeter answers greeter-caller.c1 (200)" || bad "before: $c"
[ "$(code admin -X POST -H 'Content-Type: application/json' -d "{\"serial\":\"$SER\"}" $URL/provision/revoke)" = 200 ] && ok "admin revoked greeter-caller.c1 (serial $SER)" || bad "revoke"
sleep 11
c=$(capp -o "$W/rev.out" -w "%{http_code}" -X POST https://127.0.0.1:19443/v1/hello)
[ "$c" = 403 ] && grep -q certificate_revoked "$W/rev.out" && ok "after revocation (status cache 10 s): greeter refuses it (403 certificate_revoked)" || bad "after: $c $(cat "$W/rev.out")"
[ "$(capp -o /dev/null -w "%{http_code}" $URL/v1/app/info)" = 403 ] && ok "core refuses it too" || bad "core still accepts"

echo "== 4. leave"
kill -TERM $GP $WP; wait $GP $WP 2>/dev/null
grep -q DEREGISTERED "$W/greeter.out" && grep -q DEREGISTERED "$W/worker.out" && ok "greeter and worker deregistered" || bad "leave"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
