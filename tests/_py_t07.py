import sys
from demo_swarm import build_stack, run_scenarios

notary, cv, gate, inspector, audit, middleware = build_stack()
results = run_scenarios(notary, middleware)

test = sys.argv[1]

if test == "all":
    for r in results:
        sid = r["scenario"]
        dec = r["decision"]
        gate_f = r["gate_fired"]
        leaf = r.get("leaf_hash") or "NONE"
        has_leaf = leaf != "NONE" and len(leaf) == 64
        print(sid + "|" + dec + "|" + gate_f + "|" + str(has_leaf))
