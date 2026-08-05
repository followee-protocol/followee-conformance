#!/usr/bin/env python3
"""Scripted fake adapter for campaign end-to-end tests.

Responds from a JSON script located next to this file: for a script at
``<name>.py`` the responses file is ``<name>.responses.json`` with shape:

    {
      "hello": { ...hello result... },
      "cases": { "<caseId>": {"status": "accepted", "result": {...}}
                 | {"status": "rejected", "error": "..."} }
    }

Responses are stateless, so the campaign's identical-request repetition
check passes by construction.
"""

import json
import sys
from pathlib import Path


def main() -> int:
    me = Path(__file__)
    script = json.loads(me.with_name(me.stem + ".responses.json").read_text())
    for line in sys.stdin:
        request = json.loads(line)
        case_id = request["caseId"]
        if request["operation"] == "hello":
            body = {"status": "accepted", "result": script["hello"]}
        else:
            body = script["cases"][case_id]
        response = {"runnerProtocol": "1", "caseId": case_id, **body}
        print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
