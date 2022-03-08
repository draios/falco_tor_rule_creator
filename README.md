# Falco TOR Rule Creator

## Installation
The below instructions assume [Falco](https://falco.org/) is already installed. For installation documentation visit [https://falco.org/docs/getting-started/installation/](https://falco.org/docs/getting-started/installation/).

### Host Installation
The following applies to stand alone hosts running Falco as a service.

#### System Requirements
* Python3
* Python3 PIP
* Python3 venv

#### Clone the repo
```
git clone https://github.com/draios/falco_tor_rule_creator.git
```

#### Create and activate a virtual environment
It is good practice to create a virtual environment for python applications. This allows an application to install dependancies separate from other applications and separate from the system libraries.

```
cd falco_tor_rule_creator
python3 -m venv venv
source venv/bin/activate
```

#### Install script requirements
```
pip install -r requirements.txt
```

#### Test the script
Next you will want to test the script. There are a number of configuration options, so be sure to check the `--help` output. By default the script writes to `/etc/falco/rules.d` which is read in last in a default Falco installation. You need to decide which rules to create based on whether you use IPv4, IPv6, or both, and whether you want to detect connection to/from entry nodes, exit nodes, or all nodes.

For example, to only detect outbound IPv4 connections from your host to a TOR node, you would run:
```
python sysdig_tor_node_enumerator.py --ipv4_entry
```
This should create the file `/etc/falco/rules.d/tor_ipv4_entry_nodes_rules.yaml`. To load this rule you can restart the falco service, or `kill -1` the falco process.

#### Create cronjob
The list of TOR IPs changes frequently. To keep your falco rules up to date you will need to run the script in a cron job. You will also need to reload falco after each update. The following cron entry should do the trick:

in `/etc/cron.d`
```
*/30 * * * * /path/to/venv/bin/python /path/to/falco_tor_rule_creator.py <options> && systemctl restart falco
```

### Docker installation
To run this script as a docker container you will first need to edit `app.sh` to fit your needs. Once you have updated `app.sh` you can build the image like this:
```
docker build -t falco_tor_rule_creator:latest .
```

Then run the container, making sure to mount the Falco rules directory. For example:
```
docker run --name falco_tor_rule_creator -d -v/etc/falco:/etc/falco falco_tor_rule_creator:latest
```

## Usage
```
usage: falco_tor_rule_creator.py [-h] [--debug] [--path PATH] [--severity [{emergency,alert,critical,error,warning,notice,informational,debug}]]
                                     [--ipv4_all] [--ipv4_entry] [--ipv4_exit] [--ipv6_all] [--ipv6_entry] [--ipv6_exit] [--tags TAGS [TAGS ...]]

Queries the TOR network for relay nodes and populates Falco rules to detect connections to/from them

optional arguments:
  -h, --help            show this help message and exit
  --debug, -d           Print debug information
  --path PATH, -p PATH  Path to the rules directory to write Falco rules to.
  --severity [{emergency,alert,critical,error,warning,notice,informational,debug}], -s [{emergency,alert,critical,error,warning,notice,informational,debug}]
                        Sets the priority of the rule (default: warning)
  --ipv4_all            Write Falco rule to block all ingress and egress traffic to/from any IPv4 TOR node
  --ipv4_entry          Write Falco rule to block all egress traffic to any ENTRY IPv4 TOR node
  --ipv4_exit           Write Falco rule to block all ingress traffic from any EXIT IPv4 TOR node
  --ipv6_all            Write Falco rule to block all ingress and egress traffic to/from any IPv6 TOR node
  --ipv6_entry          Write Falco rule to block all egress traffic to any ENTRY IPv6 TOR node
  --ipv6_exit           Write Falco rule to block all ingress traffic from any EXIT IPv6 TOR node
  --tags TAGS [TAGS ...], -t TAGS [TAGS ...]
                        List of tags to associate with generated Falco rules in addition to 'network' which will always be attached.
```