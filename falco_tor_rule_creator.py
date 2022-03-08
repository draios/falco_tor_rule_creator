#!/usr/bin/env python

# Tor Node collection code Adapted from PHP script at
# https://gitlab.com/fissionrelays/lists/-/blob/master/tor.php

import logging
import json
import datetime
import re
from ipaddress import ip_address, IPv4Address
import sys
import argparse

import requests
from requests.exceptions import RequestException


BASE_URL = "https://onionoo.torproject.org";

# Relay must be seen within the last 3 hours.
LAST_SEEN_WINDOW = 10800;

# Falco metadata
TOR_IPV4_ALL_NODES = {
    "list_name": "tor_ipv4_nodes",
    "rule_name": "Connection to Any TOR IPv4 Network Node",
    "file_name": f'tor_ipv4_all_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": True
}
TOR_IPV4_ENTRY_NODES = {
    "list_name": "tor_ipv4_entry_nodes",
    "rule_name": "Connection to TOR IPv4 Network Entry Node",
    "file_name": f'tor_ipv4_entry_nodes_rules.yaml',
    "ingress_rule": False,
    "egress_rule": True
}
TOR_IPV4_EXIT_NODES = {
    "list_name": "tor_ipv4_exit_nodes",
    "rule_name": "Connection to TOR IPv4 Network Exit Node",
    "file_name": f'tor_ipv4_exit_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": False
}
TOR_IPV6_ALL_NODES = {
    "list_name": "tor_ipv6_nodes",
    "rule_name": "Connection to Any TOR IPv6 Network Node",
    "file_name": f'tor_ipv6_all_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": True
}
TOR_IPV6_ENTRY_NODES = {
    "list_name": "tor_ipv6_entry_nodes",
    "rule_name": "Connection to TOR IPv6 Network Entry Node",
    "file_name": f'tor_ipv6_entry_nodes_rules.yaml',
    "ingress_rule": False,
    "egress_rule": True
}
TOR_IPV6_EXIT_NODES = {
    "list_name": "tor_ipv6_exit_nodes",
    "rule_name": "Connection to TOR IPv6 Network Exit Node",
    "file_name": f'tor_ipv6_exit_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": False
}


def pretty_print_request(req):
    logging.debug('{}\n{}\n{}\n\n'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
    ))


def is_good_response(resp):
    content_type = resp.headers['Content-Type'].lower()
    return(resp.status_code == 200 and content_type is not None)


def simple_get(url):
    logging.debug(f'URL: {url}')
    logging.debug('Fetching {}'.format(url))
    try:
        req = requests.Request('GET', url)
        prepared = req.prepare()
        pretty_print_request(prepared)

        session = requests.Session()
        resp = session.send(prepared)
        if is_good_response(resp):
            return resp.content
        else:
            return None
    except RequestException as e:
        logging.error('Error during requests to {}: {}'.format(url, str(e)))


def validIPAddress(ip):
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return None


def fetch_relays():
    logging.info('Fetching TOR Nodes')
    response_raw = simple_get(f'{BASE_URL}/details')
    try:
        response = json.loads(response_raw.decode())
    except TypeError as e:
        logging.error('Error loading json data: e')
        return None

    return response.get('relays')


def parse_addresses(relays, last_seen_window):
    logging.info('Parsing addresses out of node results')
    now = int(datetime.datetime.now().timestamp())
    addresses = {
        "ipv4_all": [],
        "ipv6_all": [],
        "ipv4_entry": [],
        "ipv6_entry": [],
        "ipv4_exit": [],
        "ipv6_exit": [],
    }

    logging.info(f'relays found: {len(relays)}')
    for relay in relays:
        is_entry = False
        is_exit = False

        # Check if it's still up
        last_seen = int(datetime.datetime.strptime(relay.get('last_seen'), "%Y-%m-%d %H:%M:%S").timestamp())
        
        if (last_seen < now - last_seen_window):
            logging.debug('Skipping old relay last seen: {}'.format(relay.get('last_seen')))
            continue

        if "Guard" in relay.get('flags', []):
            is_entry = True
        if "Exit" in relay.get('flags', []):
            is_exit = True

        for or_address in relay.get('or_addresses', []):
            or_address_matches= re.findall('^\[?([0-9a-f:.]*)]?:\d+$', or_address)
            logging.debug(f'or_address_matches: {or_address_matches}')
            for address in or_address_matches:
                ip_type = validIPAddress(address)
                if not ip_type:
                    logging.error(f"NOT A VALID IP: {address}")
                    break
                if ip_type == "IPv4" and address not in addresses['ipv4_all']:
                    addresses['ipv4_all'].append(f"'\"{address}\"'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'\"{address}\"'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'\"{address}\"'")
                if ip_type == "IPv6" and address not in addresses['ipv6_all']:
                    addresses['ipv6_all'].append(f"'\"{address}\"'")
                    if is_entry:
                        addresses['ipv6_entry'].append(f"'\"{address}\"'")
                    if is_exit:
                        addresses['ipv6_exit'].append(f"'\"{address}\"'")

        if relay.get('exit_addresses'):
            exit_addresses = relay.get('exit_addresses')
            for address in exit_addresses:
                ip_type = validIPAddress(address)
                if not ip_type:
                    break
                if ip_type == "IPv4" and address not in addresses['ipv4_all']:
                    addresses['ipv4_all'].append(f"'\"{address}\"'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'\"{address}\"'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'\"{address}\"'")
                if ip_type == "IPv6" and address not in addresses['ipv6_all']:
                    addresses['ipv6_all'].append(f"'\"{address}\"'")
                    if is_entry:
                        addresses['ipv6_entry'].append(f"'\"{address}\"'")
                    if is_exit:
                        addresses['ipv6_exit'].append(f"'\"{address}\"'")
    # Remove duplicates
    addresses['ipv4_all'] = list(set(addresses['ipv4_all']))
    addresses['ipv4_entry'] = list(set(addresses['ipv4_entry']))
    addresses['ipv4_exit'] = list(set(addresses['ipv4_exit']))
    addresses['ipv6_all'] = list(set(addresses['ipv6_all']))
    addresses['ipv6_entry'] = list(set(addresses['ipv6_entry']))
    addresses['ipv6_exit'] = list(set(addresses['ipv6_exit']))
    return addresses

def write_falco_rule(rule, addresses, args):
    logging.info(f'Writing Falco rule {rule["file_name"]}')
    file_text = build_falco_rule(rule,addresses, args.tags, args.severity)
    try:
        with open(f'{args.path}/{rule["file_name"]}', "w") as fh:
            fh.write(file_text)
    except PermissionError as e:
        logging.error(f'Error writing file {rule["file_name"]}: {e}')

def build_falco_rule(rule, addresses, tags, severity):
    description = """
#########################
# TOR Node Rule
#########################
    
# This rule is auto-generated and should not be edited manually!
# Rule checks for communication with known TOR relay nodes.

---"""
    list = f"""
- list: "{rule['list_name']}"
  items:
"""
    for address in addresses:
        list = list + f"  - {address}\n"
    list = list + "  append: false\n"

    rule_text = ""
    for direction in ['ingress', 'egress']:
        if direction == "ingress":
            fd = "fd.cip"
            type = "accept"
            output = "Detected connection from known TOR Node to pod or host."
        else:
            fd = "fd.sip"
            type = "connect"
            output = "Detected connection to known TOR Node from pod or host."

        if not rule[f'{direction}_rule']:
            _rule = ""
        else:
            _rule = f"""
- rule: "{rule['rule_name']} ({direction})"
  desc: "Connections detected in pod or host. The rule was triggered by addresses known to be TOR Nodes"
  condition: "evt.type = {type} and evt.dir = < and {fd} in ({rule['list_name']})"
  output: "{output} %proc.cmdline %evt.args"
  priority: "{severity}"
  tags:
  - "network"
"""
        for tag in tags:
            _rule = _rule + f"  - \"{tag}\"\n"
        _rule = _rule + """  source: "syscall"
  append: false

"""
        rule_text = rule_text + _rule

    file_text = description + list + rule_text
    return file_text    

def parse_args():
    parser = argparse.ArgumentParser(description="Queries the TOR network for relay nodes and populates Falco rules to detect connections to/from them")
    parser.add_argument(
        "--debug", "-d", dest='debug', action="store_true", default=False,
        help="Print debug information"
    )
    parser.add_argument(
        "--path", "-p", type=str, dest='path', default="/etc/falco/rules.d",
        help="Path to the rules directory to write Falco rules to."
    )
    parser.add_argument(
        "--severity", "-s", dest='severity', default="warning", nargs="?",
        choices=["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"],
        help="Sets the priority of the rule (default: %(default)s)"
    )
    parser.add_argument(
        "--ipv4_all", dest="ipv4_all", action="store_true", default=False,
        help="Write Falco rule to block all ingress and egress traffic to/from any IPv4 TOR node"
    )
    parser.add_argument(
        "--ipv4_entry", dest="ipv4_entry", action="store_true", default=False,
        help="Write Falco rule to block all egress traffic to any ENTRY IPv4 TOR node"
    )
    parser.add_argument(
        "--ipv4_exit", dest="ipv4_exit", action="store_true", default=False,
        help="Write Falco rule to block all ingress traffic from any EXIT IPv4 TOR node"
    )
    parser.add_argument(
        "--ipv6_all", dest="ipv6_all", action="store_true", default=False,
        help="Write Falco rule to block all ingress and egress traffic to/from any IPv6 TOR node"
    )
    parser.add_argument(
        "--ipv6_entry", dest="ipv6_entry", action="store_true", default=False,
        help="Write Falco rule to block all egress traffic to any ENTRY IPv6 TOR node"
    )
    parser.add_argument(
        "--ipv6_exit", dest="ipv6_exit", action="store_true", default=False,
        help="Write Falco rule to block all ingress traffic from any EXIT IPv6 TOR node"
    )
    parser.add_argument(
        "--tags", "-t", dest="tags", nargs='+', default=[],
        help="List of tags to associate with generated Falco rules in addition to 'network' which will always be attached." 
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    logging.basicConfig(level=logging_level)
    
    # Fetch TOR Nodes
    relays = fetch_relays();
    if not relays:
        logging.error('Errors: No relays found')
        sys.exit(1)

    # Parse out the addresses
    addresses = parse_addresses(relays, LAST_SEEN_WINDOW)
    logging.debug(f' IPv4: {len(addresses["ipv4_all"])}')
    logging.debug(f' IPv4 Entry: {len(addresses["ipv4_entry"])}')
    logging.debug(f' IPv4 Exit: {len(addresses["ipv4_exit"])}')

    logging.debug(f' IPv6: {len(addresses["ipv6_all"])}')
    logging.debug(f' IPv6 Entry: {len(addresses["ipv6_entry"])}')
    logging.debug(f' IPv6 Exit: {len(addresses["ipv6_exit"])}')
    
    # Write Rules files
    if args.ipv4_all:
        write_falco_rule(TOR_IPV4_ALL_NODES, addresses['ipv4_all'], args)
    if args.ipv4_entry:
        write_falco_rule(TOR_IPV4_ENTRY_NODES, addresses['ipv4_entry'], args)
    if args.ipv4_exit:
        write_falco_rule(TOR_IPV4_EXIT_NODES, addresses['ipv4_exit'], args)

    if args.ipv6_all:
        write_falco_rule(TOR_IPV6_ALL_NODES, addresses['ipv6_all'], args)
    if args.ipv6_entry:
        write_falco_rule(TOR_IPV6_ENTRY_NODES, addresses['ipv6_entry'], args)
    if args.ipv6_exit:
        write_falco_rule(TOR_IPV6_EXIT_NODES, addresses['ipv6_exit'], args)
