import sys, time
from app.identity import CovenantNotary

test = sys.argv[1]

if test == "1":
    n = CovenantNotary()
    n.register_agent("agent-a")
    t = n.issue_token("agent-a")
    ok, msg = n.validate_token(t)
    print(str(ok) + "|" + msg + "|" + t.agent_id)

elif test == "2":
    n = CovenantNotary()
    try:
        n.issue_token("unknown")
        print("NO_ERROR")
    except ValueError as e:
        print("ERROR|" + str(e))

elif test == "3":
    n = CovenantNotary(ttl_seconds=1)
    n.register_agent("agent-b")
    t = n.issue_token("agent-b")
    time.sleep(2)
    ok, msg = n.validate_token(t)
    print(str(ok) + "|" + msg)

elif test == "4":
    n = CovenantNotary()
    n.register_agent("agent-c")
    print(str(n.is_registered("agent-c")) + "|" + str(n.is_registered("ghost")))
