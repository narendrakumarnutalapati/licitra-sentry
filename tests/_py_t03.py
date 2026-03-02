import sys, time
from app.identity import CovenantNotary, SignedToken
from app.contract import AgenticSafetyContract, ContractValidator
from app.authority import AuthorityGate

test = sys.argv[1]

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("coder")

cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="coder",
    allowed_intents=["FILE_WRITE", "RUN_TEST"],
    allowed_tools=["editor", "test_runner"],
))

gate = AuthorityGate(notary, cv)

if test == "1":
    t = notary.issue_token("coder")
    r = gate.check(t, "FILE_WRITE", "editor")
    print(r.decision)
elif test == "2":
    expired = SignedToken(
        agent_id="coder",
        issued_at=time.time() - 120,
        expires_at=time.time() - 60,
        allowed_contract_version="v1",
        signature_hex="00" * 64,
        payload_hash="00" * 32,
    )
    r = gate.check(expired, "FILE_WRITE", "editor")
    print(r.decision + "|" + r.reason)
elif test == "3":
    t = notary.issue_token("coder")
    r = gate.check(t, "DELETE_ALL", "editor")
    print(r.decision + "|" + r.reason)
elif test == "4":
    t = notary.issue_token("coder")
    r = gate.check(t, "FILE_WRITE", "rm_tool")
    print(r.decision + "|" + r.reason)
