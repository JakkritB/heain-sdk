#!/usr/bin/env bash
# heain-sdk live test 3c: jobs, P5, P7, offline mode and journal through a
# real heain-core.
#  A (one node G): ops-app submits jobs, worker-app claims and runs them
#    with the SDK's Worker (lease, formal audit per attempt, reasoning
#    record, permanent vs retryable failure); ops-app asks P5 and waits for
#    the Approver; ops-app broadcasts (P7, through P5).
#  B (G <- S1, G <- W through a proxy): the apps run on W. Cutting the proxy
#    makes W standalone: the SDK sees the mode change, the allowed
#    capability still runs on the island, the other is refused; the app's
#    journal events get durable app_seq numbers that survive a restart;
#    after the partition heals the journal reaches G, nothing lost or
#    doubled.
# Needs ~/heain-core (its test harness builds the core node). ~6 min.
# Run from ~/heain-sdk:  bash scripts/live_3c.sh
set -uo pipefail
SDK=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/sdk-3c
URL=https://127.0.0.1:18000
GW=https://127.0.0.1:18003
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
aud() { as admin "$1/v1/admin/audit?limit=3000" | python3 -c "
import json,sys
E=[r['event'] for r in json.load(sys.stdin)['records']]
def app(cap=None,res=None): return [e for e in E if e['Action']=='app.event' and (cap is None or e['Detail'].get('capability')==cap) and (res is None or e['Result']==res)]
def tk(e): return (e['Detail'].get('detail') or {}).get('ticket_id')
print($2)" 2>/dev/null; }
prov() {
  openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
  openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.tok"; }
# approve <out-file> <core-url>: approves the registration action printed by an example app (if any)
approve() { local a; for i in $(seq 1 20); do grep -q REGISTERED "$1" && break; sleep 1; done
  a=$(grep -o "action=[^ ]*" "$1" | head -1 | cut -d= -f2)
  [ -z "$a" ] || [ "$(code approver-1 -X POST $2/v1/admin/policy/$a/approve)" = 200 ]; }
COMMONF="-ca=$C/ca.pem -admin-node-id=admin -approver-ids=approver-1"
COMMON="-ca $C/ca.pem -chain $W/prov.pem"
OPS="$W/ops $COMMON -manifest $SDK/examples/ops/heain-app.yaml -app-id ops-app"
# ops <out> <args...>: runs ops-app once (first run enrolls)
ops() { local out=$1; shift; timeout 120 $OPS "$@" > "$out" 2>&1; }

echo "== A0. node G (P5, P7, jobs, provisioning); build the examples"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done; prov
echo '{"zones":{"zone-a":[]}}' > "$T/topology.json"
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=GLOBAL_PRIMARY -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" $COMMONF -bootstrap=true \
  -ingest-queue-path="$T/data-G/queue.db" -staging-path="$T/data-G/staging.db" -approval-store-path="$T/data-G/approvals.db" \
  -broadcast-topology-file="$T/topology.json" -broadcast-global-addr=https://127.0.0.1:18000 -broadcast-global-node-id=G \
  -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
( cd "$SDK" && for x in worker ops; do GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/$x" ./examples/$x || exit 1; done ) && ok "examples build" || { bad "SDK build"; exit 1; }

echo "== A1. worker-app runs jobs submitted by ops-app"
token worker-app.k1; token ops-app.o1
"$W/worker" $COMMON -core $URL -core-id G -manifest "$SDK/examples/worker/heain-app.yaml" -app-id worker-app -instance k1 \
  -cert "$W/k1.pem" -key "$W/k1.key" -enroll-token-json "$W/worker-app.k1.tok" > "$W/worker-A.out" 2>&1 &
WP=$!
approve "$W/worker-A.out" $URL && ok "worker-app enrolled and admitted" || bad "worker: $(cat "$W/worker-A.out")"
O1="-core $URL -core-id G -instance o1 -cert $W/o1.pem -key $W/o1.key"
$OPS $O1 -enroll-token-json "$W/ops-app.o1.tok" -do job -payload hello > "$W/a1.out" 2>&1 &
OP=$!; approve "$W/a1.out" $URL || bad "ops approve: $(cat "$W/a1.out")"; wait $OP
grep -q "JOB .* state=completed attempts=1 out=HELLO" "$W/a1.out" && ok "job text.upper completed: HELLO" || bad "job: $(cat "$W/a1.out")"
T1=$(grep -o "^JOB [^ ]*" "$W/a1.out" | cut -d' ' -f2)
[ "$(aud $URL "sum(1 for e in app('text.upper','ok') if tk(e)=='$T1')")" = 1 ] && [ "$(aud $URL "[e['Actor'] for e in app('text.upper') if tk(e)=='$T1'][0]")" = worker-app.k1 ] \
  && ok "the run is audited once by worker-app.k1 (formal, outcome ok)" || bad "job audit"
ops "$W/a2.out" $O1 -do job -payload corrupt
grep -q "state=retries_exhausted" "$W/a2.out" && [ "$(grep -c "text.upper attempt" "$W/worker-A.out")" = 2 ] && ok "a permanent failure is not retried (stopped, goes to the Approver)" || bad "permanent: $(cat "$W/a2.out")"
T2=$(grep -o "^JOB [^ ]*" "$W/a2.out" | cut -d' ' -f2)
[ "$(aud $URL "[e['Result'] for e in app('text.upper') if tk(e)=='$T2']")" = "['error:job_failed']" ] && ok "its attempt is audited as error:job_failed" || bad "permanent audit"
ops "$W/a3.out" $O1 -do job -payload flaky
T3=$(grep -o "^JOB [^ ]*" "$W/a3.out" | cut -d' ' -f2)
grep -q "state=completed attempts=2 out=FLAKY" "$W/a3.out" && grep -q "RAN $T3 text.upper attempt=2" "$W/worker-A.out" && ok "a retryable failure is retried by core and then completes" || bad "flaky: $(cat "$W/a3.out")"
[ "$(aud $URL "sorted(e['Result'] for e in app('text.upper') if tk(e)=='$T3')")" = "['error:job_failed', 'ok']" ] && ok "one audit event per attempt (failed, then ok)" || bad "flaky audit: $(aud $URL "[e['Result'] for e in app('text.upper') if tk(e)=='$T3']")"
ops "$W/a4.out" $O1 -do job -cap text.tone -payload "great news!!"
T4=$(grep -o "^JOB [^ ]*" "$W/a4.out" | cut -d' ' -f2)
grep -q "state=completed .*out=loud" "$W/a4.out" && ok "AI job text.tone completed: loud" || bad "tone: $(cat "$W/a4.out")"
[ "$(aud $URL "len([r for r in E if r['Action']=='ai.reasoning_record' and r['Detail']['record_id'] in [i for e in app('text.tone','ok') if tk(e)=='$T4' for i in e['Detail']['detail']['reasoning_record_ids']] and r['Detail']['trace_id']==[e for e in app('text.tone','ok') if tk(e)=='$T4'][0]['Detail']['trace_id']])")" = 1 ] \
  && ok "its signed reasoning record is in core's audit, linked to the job's event (same trace)" || bad "tone record"
as admin "$URL/v1/admin/audit?limit=3000" | grep -q "great news" && bad "raw AI input reached core's audit" || ok "the job's raw input is not in the audit"
ops "$W/a5.out" $O1 -do job -cap image.upscale
grep -q "ERROR stage=submit err=.*not declared in the manifest's uses" "$W/a5.out" && ok "a job for a capability not in uses[] is refused before any call" || bad "uses: $(cat "$W/a5.out")"

echo "== A2. P5 and P7"
$OPS $O1 -do propose -type grant.extend -category ALLOWLIST_BASED > "$W/p1.out" 2>&1 &
OP=$!; for i in $(seq 1 20); do grep -q PROPOSED "$W/p1.out" && break; sleep 1; done
PA=$(grep -o "^PROPOSED [^ ]*" "$W/p1.out" | cut -d' ' -f2)
grep -q "PROPOSED .* result=WAITING_APPROVAL" "$W/p1.out" && ok "proposal outside policy waits for an Approver ($PA)" || bad "propose: $(cat "$W/p1.out")"
sleep 3; [ "$(code approver-1 -X POST $URL/v1/admin/policy/$PA/approve)" = 200 ] || bad "approve P5"
wait $OP
grep -q "DECIDED $PA result=APPROVED" "$W/p1.out" && ok "the app's WaitPolicy saw the Approver's decision: APPROVED" || bad "decided: $(cat "$W/p1.out")"
$OPS $O1 -do propose -type grant.extend -category ALLOWLIST_BASED > "$W/p2.out" 2>&1 &
OP=$!; for i in $(seq 1 20); do grep -q PROPOSED "$W/p2.out" && break; sleep 1; done
PB=$(grep -o "^PROPOSED [^ ]*" "$W/p2.out" | cut -d' ' -f2)
code approver-1 -X POST $URL/v1/admin/policy/$PB/reject >/dev/null; wait $OP
grep -q "DECIDED $PB result=DENIED" "$W/p2.out" && ok "rejected -> DENIED" || bad "denied: $(cat "$W/p2.out")"
ops "$W/p3.out" $O1 -do propose -type x.y -category SYSTEM_SURVIVAL
grep -q "ERROR stage=propose code=policy_rejected" "$W/p3.out" && ok "SYSTEM_SURVIVAL is refused to apps" || bad "survival: $(cat "$W/p3.out")"
ops "$W/b1.out" $O1 -do broadcast -discovery d1 -zone zone-a
BA=$(grep -o "^BROADCAST [^ ]*" "$W/b1.out" | cut -d' ' -f2)
grep -q "BROADCAST .* result=WAITING_APPROVAL" "$W/b1.out" && ok "broadcast goes through P5 ($BA)" || bad "broadcast: $(cat "$W/b1.out")"
code approver-1 -X POST $URL/v1/admin/policy/$BA/approve >/dev/null; sleep 2
rec=$(as admin $URL/broadcast/received); echo "$rec" | grep -q lighting-adjust && ! echo "$rec" | grep -q '"c1"' && ok "approved -> sanitized and delivered (customer id removed)" || bad "broadcast delivery: $rec"
kill -TERM $WP; wait $WP 2>/dev/null
grep -q DEREGISTERED "$W/worker-A.out" && ok "worker SIGTERM -> deregistered" || bad "worker leave"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"
$H stop-all >/dev/null 2>&1; sleep 2

echo "== B0. G <- S1 (direct), G <- W (through a proxy); the apps on W"
proxy_up() { nohup python3 - > "$L/proxy.log" 2>&1 <<'PYEOF' &
import asyncio
async def pipe(r, w):
    try:
        while (d := await r.read(65536)):
            w.write(d); await w.drain()
    except Exception: pass
    finally: w.close()
async def handle(cr, cw):
    try:
        ur, uw = await asyncio.open_connection('127.0.0.1', 18000)
    except Exception:
        cw.close(); return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
async def main():
    s = await asyncio.start_server(handle, '127.0.0.1', 28000)
    async with s: await s.serve_forever()
asyncio.run(main())
PYEOF
  echo $! > "$P/proxy.pid"; sleep 1; }
proxy_down() { kill -9 "$(cat "$P/proxy.pid")" 2>/dev/null; rm -f "$P/proxy.pid"; }
node() { # <id> <port> <raft> <promote-raft> <G-base>
  nohup "$BIN" -node-id=$1 -tier=WORKER -raft-addr=127.0.0.1:$3 -data-dir="$T/data-$1" -http-addr=127.0.0.1:$2 \
    -cert="$C/$1.pem" -key="$C/$1.key" $COMMONF -bootstrap=false \
    -parent-addr=$5/health -parent-node-id=G -promote-raft-addr=127.0.0.1:$4 -promote-data-dir="$T/promote-$1" \
    -ingest-queue-path="$T/data-$1/queue.db" -staging-path="$T/data-$1/staging.db" -approval-store-path="$T/data-$1/approvals.db" \
    -farm-register-addr=$5 -farm-register-node-id=G -self-addr=https://127.0.0.1:$2 -farm-register-interval=2s >> "$L/$1.log" 2>&1 &
  echo $! > "$P/$1.pid"; }
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
rm -rf "$W"; mkdir -p "$L" "$P" "$T/data-G" "$T/data-S1" "$T/data-W" "$T/promote-S1" "$T/promote-W" "$W"; for c in admin approver-1; do mkcert $c; done; prov
( cd "$SDK" && for x in worker ops; do GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/$x" ./examples/$x || exit 1; done )
: > "$L/G.log"; : > "$L/S1.log"; : > "$L/W.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" $COMMONF -bootstrap=true \
  -ingest-queue-path="$T/data-G/queue.db" -staging-path="$T/data-G/staging.db" -approval-store-path="$T/data-G/approvals.db" \
  -farm-registry-ttl=30s -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
proxy_up
node S1 18005 19005 19006 https://127.0.0.1:18000
node W 18003 19003 19004 https://127.0.0.1:28000
sleep 8
token worker-app.w1; token ops-app.o2
ONW="-core $GW -core-id W -enroll-core $URL -enroll-core-id G"
"$W/worker" $COMMON $ONW -manifest "$SDK/examples/worker/heain-app.yaml" -app-id worker-app -instance w1 \
  -cert "$W/w1.pem" -key "$W/w1.key" -enroll-token-json "$W/worker-app.w1.tok" > "$W/worker-B.out" 2>&1 &
WP=$!
approve "$W/worker-B.out" $GW || bad "worker on W: $(cat "$W/worker-B.out")"
for i in $(seq 1 20); do grep -q WORKING "$W/worker-B.out" && break; sleep 1; done
grep -q WORKING "$W/worker-B.out" && ok "worker-app.w1 runs on W (enrolled at G, registered with W's core)" || bad "worker on W: $(cat "$W/worker-B.out")"
O2="$ONW -instance o2 -cert $W/o2.pem -key $W/o2.key"
$OPS $O2 -enroll-token-json "$W/ops-app.o2.tok" -do mode > "$W/m0.out" 2>&1 &
OP=$!; approve "$W/m0.out" $GW || bad "ops on W approve"; wait $OP
grep -q "^MODE normal" "$W/m0.out" && ok "ops-app on W: mode normal" || bad "mode: $(cat "$W/m0.out")"

sleep 15 # W's escrow copy of G's state (escrow.sync_interval 10 s) must include the two new app certificates

echo "== B1. partition: W is cut off from G (G and S1 stay up)"
proxy_down
for i in $(seq 1 20); do grep -q "STANDALONE: cut off" "$L/W.log" && break; sleep 2; done
grep -q "STANDALONE: cut off" "$L/W.log" && ok "W core: STANDALONE" || bad "W not standalone: $(grep -iE "partition|STANDALONE" "$L/W.log" | tail -2)"
for i in $(seq 1 15); do grep -q "SELF-PROMOTED" "$L/W.log" && break; sleep 2; done
grep -q "SELF-PROMOTED" "$L/W.log" || bad "W did not promote (Emergency Exception)"
for i in $(seq 1 15); do grep -q "^MODE standalone" "$W/worker-B.out" && break; sleep 1; done
grep -q "^MODE standalone" "$W/worker-B.out" && ok "the running worker's OnModeChange fired: standalone" || bad "worker mode: $(tail -3 "$W/worker-B.out")"
ops "$W/m1.out" $O2 -do mode
grep -q "^MODE standalone" "$W/m1.out" && ok "FetchMode: standalone" || bad "mode: $(cat "$W/m1.out")"
ops "$W/b1.out" $O2 -do job -payload island
grep -q "state=completed .*out=ISLAND" "$W/b1.out" && ok "text.upper (in offline.allowed) still runs on the island" || bad "island job: $(cat "$W/b1.out")"
ops "$W/b2.out" $O2 -do job -cap text.tone -payload "hi!!"
grep -q "ERROR stage=submit code=standalone_not_allowed" "$W/b2.out" && ok "text.tone (not in offline.allowed) is refused while standalone" || bad "tone offline: $(cat "$W/b2.out")"
ops "$W/j1.out" $O2 -do journal -kind vote.counted -n 2
ops "$W/j2.out" $O2 -do journal -kind vote.counted -n 1
[ "$(grep -o "app_seq=[0-9]*" "$W/j1.out" "$W/j2.out" | cut -d= -f2 | tr '\n' ' ')" = "1 2 3 " ] \
  && ok "journal events get app_seq 1, 2 and, after a restart of the app, 3 (durable counter)" || bad "journal: $(cat "$W/j1.out" "$W/j2.out")"
ops "$W/s1.out" $O2 -do journal-status
grep -q "JOURNAL-STATUS state=pending" "$W/s1.out" && ok "journal status while cut off: pending" || bad "status: $(cat "$W/s1.out")"

echo "== B2. the partition heals"
proxy_up
for i in $(seq 1 40); do grep -q "RECONNECTED: leaving STANDALONE" "$L/W.log" && break; sleep 3; done
grep -q "RECONNECTED: leaving STANDALONE" "$L/W.log" && ok "W reconnected" || bad "no reconnect: $(tail -3 "$L/W.log")"
for i in $(seq 1 20); do grep -q "^MODE normal" "$W/worker-B.out" && break; sleep 1; done
grep -q "^MODE normal" "$W/worker-B.out" && ok "the worker's OnModeChange fired: normal" || bad "worker back: $(tail -3 "$W/worker-B.out")"
for i in $(seq 1 40); do ops "$W/s2.out" $O2 -do journal-status; grep -q "state=acked" "$W/s2.out" && break; sleep 3; done
grep -q "JOURNAL-STATUS state=acked" "$W/s2.out" && ok "journal acknowledged by G ($(grep JOURNAL-STATUS "$W/s2.out"))" || bad "status: $(cat "$W/s2.out")"
[ "$(aud $URL "sum(1 for e in E if e['Action']=='journal.merged' and e['Result']=='app:vote.counted')")" = 3 ] && ok "G has the app's 3 vote.counted events -- none lost, none doubled" || bad "merged app events: $(aud $URL "sum(1 for e in E if e['Action']=='journal.merged' and e['Result']=='app:vote.counted')")"
[ "$(aud $URL "sum(1 for e in E if e['Action']=='journal.merged' and e['Result']=='core:app.event' and 'text.upper' in e['Detail']['entry'])")" -ge 1 ] \
  && ok "the SDK's formal audit of the island job reached G through the journal" || bad "island audit not merged"
kill -TERM $WP; wait $WP 2>/dev/null
v1=$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']"); v2=$(as admin "$GW/v1/admin/audit/verify" | j "d['ok']")
[ "$v1" = True ] && [ "$v2" = True ] && ok "audit chains verify on G and W" || bad "audit verify: G=$v1 W=$v2"

echo "== cleanup"
proxy_down; $H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
