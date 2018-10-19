#!/usr/bin/python3
import requests
import json

def testAPIConnection(url, key):
    """Attempts to connect to the Burp API with a URL that includes the API key."""
    try:
        resp = requests.get(url + key, verify=False)
        print(resp)
        print(resp.status_code)
        print(type(resp.status_code))
        if resp.status_code == 200:
            return 1
        else:
            print('Invalid API URL or Key. Server Response: {}'.format(resp.status_code))
            return 2
    except Exception as e:
        print(e)
        print("exception")
    print("final return")
    return 3

def startBurpScan(url, key, target, scope, creds):
    """Initiates request to the Burp API to start a scan for a specified
    target URL. Scope is limited to the URL by default to prevent going
    out of the scope of the url being scanned.
    """
    # Tests connection to the API. Exits the function if unsuccessful.
    if not burp2.testAPIConnection(url, key):
        return False
    api_scan_url = url + key + '/scan'

    # Automatically sets the scope to the URL. This prevents the scanner
    # to scan out of the scope of the URL you are providing.
    data = {
        "scope": {"include": [] },
        "urls": [target],
        "application_logins": []
    }
    for item in scope:
        data["scope"]["include"] += {"rule": item, "type": "SimpleScopeDef"}
    for cred in creds:
        data["application_logins"] += {"password": cred[1], "username": cred[0]}
    try:
        resp = requests.post(api_scan_url, json=data)
    except Exception as e:
        return False
    if resp.status_code == 201:
        scan_id = resp.headers.get('location')
        return scan_id
    else:
        return False

def checkBurpScan(url, key, scanID):
    if not burp2.testAPIConnection(url, key):
        print("api returned false")
        #return False
    api_scan_url = url + key + '/v0.1/scan/' + scanID
    resp = requests.get(api_scan_url)
    print(resp)
    print(resp.status_code)
    if resp.status_code is not 200:
        return False
    print(resp.json())
    return resp.json()

def issueDefinitions(url, key):
    if not burp2.testAPIConnection(url, key):
        print("api returned false")
        return False
    api_scan_url = url + key + "/v0.1/knowledge_base/issue_definitions"
    resp = requests.get(api_scan_url)
    print(resp)
    print(resp.status_code)
    if resp.status_code is not 200:
        return False
    print(resp.json())
    return resp.json()

def defineIssues(scanIssues, definitions):
    retIssues = []
    definitions = dict([(D["issue_type_id"], burp2.pop(D, "issue_type_id")) for D in definitions])
    # Definitions is now a dict of issue_type_id: issue_data.
    for issue in scanIssues["issue_events"]:
        ret = issue
        number = str(issue["issue"]["type_index"])
        if number in definitions.keys():
            print("found")
            if "description" in definitions[number].keys():
                ret["issue"]["issue_description"] = definitions[number]["description"]
            if "remediation" in definitions[number].keys():
                ret["issue"]["issue_remediation"] = definitions[number]["remediation"]
            if "vulnerability_classifications" in definitions[number].keys():
                ret["issue"]["issue_vulnerability_classifications"] = definitions[number]["vulnerability_classifications"]
            if "references" in definitions[number].keys():
                ret["issue"]["issue_references"] = definitions[number]["references"]
        else:
            print("not found " + number)
            continue
    return retIssues

def pop(x, k):
    """Returns copy of dict `x` without key `k`."""
    x = copy.copy(x)
    del x[k]
    return x

def getIssues(url, key, scanID):
    scanIssues = burp2.checkBurpScan(url, key, scanID)
    definitions = burp2.issueDefinitions(url, key)
    issues = defineIssues(scanIssues, definitions)
    return issues

