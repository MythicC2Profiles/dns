from mythic_c2_container.C2ProfileBase import *
import sys
import json
import re

# request is a dictionary: {"action": func_name, "message": "the input",  "task_id": task id num}
# must return an RPCResponse() object and set .status to an instance of RPCStatus and response to str of message
async def test(request):
    response = RPCResponse()
    response.status = RPCStatus.Success
    response.response = "hello"
    resp = await MythicRPC().execute("create_event_message", message="Test message", warning=False)
    return response


# The opsec function is called when a payload is created as a check to see if the parameters supplied are good
# The input for "request" is a dictionary of:
# {
#   "action": "opsec",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def opsec(request):
    if request["parameters"]["msginit"] == "app":
        return {"status": "error", "error": "Prefix of initial query is set to default value: \"app\"!\n"}
    if request["parameters"]["msgdefault"] == "dash":
        return {"status": "error", "error": "Prefix of default queries is set to default: \"dash\"!\n"}
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
    match_re = re.compile(reg)
    res = re.search(match_re, request["parameters"]["hmac_key"])
    if res:
        pass
    else:
        return {"status": "error", "error": "The HMAC Key requires at least 12 characters including one capital letter, one number and special character.\n"}
    return {"status": "success", "message": "Basic OPSEC Check Passed\n"}

async def config_check(request):
    try:
        with open("../c2_code/config.json") as f:
            config = json.load(f)
            for inst in config["instances"]:
                check_msginit = False
                check_msgdefault = False
                check_callback_domains = False
                check_hmac_key = False
                if request["parameters"]["msginit"] == inst["msginit"]:
                    check_msginit = True
                if request["parameters"]["msgdefault"] == inst["msgdefault"]:
                    check_msgdefault = True
                if request["parameters"]["callback_domains"] == inst["callback_domains"]:
                    check_callback_domains = True
                if request["parameters"]["hmac_key"] == inst["hmac_key"]:
                    check_hmac_key = True
            if check_msginit and check_msgdefault and check_callback_domains and check_hmac_key:
                message = f"All Checks passed.\n"
                message += f"Generating payload.\n"
                return {"status": "success", "message": message}
            else:
                message = f"One or more checks failed.\n"
                message += f"The payload parameters should match the instance paremeters. \n"
                return {"status": "error", "message": message}
    except Exception as e:
        return {"status": "error", "error": str(e)}
