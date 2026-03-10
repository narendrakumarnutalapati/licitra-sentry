import sys
from app.contract import AgenticSafetyContract, ContractValidator, ParameterShape

test = sys.argv[1]

cv = ContractValidator()
c = AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ", "SUMMARIZE"],
    allowed_tools=["web_search", "doc_reader"],
    parameter_shapes={
        "READ": [
            ParameterShape(name="source", type="str"),
            ParameterShape(name="path", type="str", pattern=r"^/safe/.*"),
        ]
    },
)
cv.register_contract(c)

if test == "1":
    r = cv.validate_intent("researcher", "READ")
    print(r.decision)
elif test == "2":
    r = cv.validate_intent("researcher", "DELETE")
    print(r.decision + "|" + r.reason)
elif test == "3":
    r = cv.validate_tool("researcher", "web_search")
    print(r.decision)
elif test == "4":
    r = cv.validate_tool("researcher", "shell_exec")
    print(r.decision + "|" + r.reason)
elif test == "5":
    r = cv.validate_parameters("researcher", "READ", {"source": "report.pdf", "path": "/safe/docs/r.pdf"})
    print(r.decision)
elif test == "6":
    r = cv.validate_parameters("researcher", "READ", {"source": "report.pdf", "path": "/etc/passwd"})
    print(r.decision + "|" + r.reason)
elif test == "7":
    r = cv.validate_intent("ghost", "READ")
    print(r.decision + "|" + r.reason)
