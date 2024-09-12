
# IPscalper
```
    ooOoOOo OooOOo.                      o                    
       O    O     `O                    O                     
       o    o      O                    o                     
       O    O     .o                    O                     
       o    oOooOO'  .oOo  .oOo  .oOoO' o  .oOo. .oOo. `OoOo. 
       O    o        `Ooo. O     O   o  O  O   o OooO'  o     
       O    O            O o     o   O  o  o   O O      O     
    ooOOoOo o'       `OoO' `OoO' `OoO'o Oo oOoO' `OoO'  o     
                                           O                  
                                           o'  pbwbb                
    
```
## Description

IPscalper is an open-source tool designed for comprehensive IP address analysis. By integrating multiple APIs, it provides extensive data, including geographical location, reputation, associated threats (IoCs), and open ports.

You can use this Script to get parsed or raw results from these tools:
* Ping with Check-Host.net
* VirusTotal (including WHOIS)
* AbuseIPdb 
* OTX ALienVault 
* CriminalIP 
* IP-api location
* Feodo tracker by abuse.ch
* GreyNoise
* ThreatFox by abuse.ch
## Requirements

- Python 3
- API keys for certain features 

## API keys
* All APIs used in this script are free although some require you to create an account in order to get a key
* Read the documentation and be aware of the usage limits of each tool

Tools that require API keys

* VirusTotal (https://docs.virustotal.com/reference/overview) 
* AbuseIPdb (https://www.abuseipdb.com/api.html)
* OTX ALienVault (https://otx.alienvault.com/assets/static/external_api.html)
* CriminalIP (https://www.criminalip.io/developer/api-integrations)
* GreyNoise (https://docs.greynoise.io/reference/get_v3-community-ip)


## Installation

```
git clone https://github.com/pbwbb/IPscalper
pip install requests argparse urllib3
````
Edit the "API_keys.txt" and input the API keys if you wish to use the tools that require them, insert as "Tool:key" do not use "" on the keys

Example API_keys.txt:
```
VirusTotal:494e56414c49445f4150495f4b45595f31323334353637383930
AbuseIPdb:494e56414c49445f4150495f4b45595f31323334353637383930
OTX:494e56414c49445f4150495f4b45595f31323334353637383930
CriminalIP:494e56414c49445f4150495f4b45595f31323334353637383930
GreyNoise:494e56414c49445f4150495f4b45595f31323334353637383930
```
## usage
```
python IPscalper.py [options] <IP address>
```
* Not providing any options will be the same as using the -nokey option
## help menu

```
usage: IPscalper [-h] [-all] [-geo] [-raw] [-ping] [-vt] [-abuse] [-otx] [-showkeys] [-criminalip] [-c2] [-threatfox] [-gn] [-nokey] [-nobanner] IP

A tool for finding open source information about IP addresses All tools used on this script are free, although API keys are necessary for some of them. To get  
the keys you only need to create an account. Be mindiful of API limits. I am not responsible for any misuse of APIs or tools on this script

positional arguments:
  IP                   IP address that is going to be searched****

options:
  -h, --help           show this help message and exit
  -all                 Uses all tools
  -geo, --location     Uses IP-api to get IP location (no key needed)
  -raw                 Displays raw json output
  -ping                Uses check-host.net to ping the IP form multiple hosts (no key needed)
  -vt, --VirusTotal    Uses VirusTotal API for info (key required -> edit API_keys.txt file or uncomment lines)
  -abuse, --AbuseIPdb  Uses AbuseIPdb API for info (key required -> edit API_keys.txt file or uncomment lines)
  -otx, --AlienVault   Uses OTX AlienVault API for info (key required -> edit API_keys.txt file or uncomment lines)
  -showkeys            display API keys
  -criminalip          Uses CriminalIP api for info (key required -> edit API_keys.txt file or uncomment lines)
  -c2, --Feodo         Checks if IP is in Abuse.ch Feodo tracker last 30 days C2 IoCs (no key needed)
  -threatfox           Uses abuse.ch ThreatFox API for info (no key needed)
  -gn, --greynoise     Uses GreyNoise API for info (key required -> edit API_keys.txt file or uncomment lines)
  -nokey               Only uses tools that do not require an API key
  -nobanner            Do not display banner

https://github.com/pbwbb/IPscalper pb![image](https://github.com/user-attachments/assets/809cf302-9f39-42ff-a6ab-0cdf218e4557)
wbb
```
## Example output

```

    ooOoOOo OooOOo.                      o
       O    O     `O                    O
       o    o      O                    o
       O    O     .o                    O
       o    oOooOO'  .oOo  .oOo  .oOoO' o  .oOo. .oOo. `OoOo.
       O    o        `Ooo. O     O   o  O  O   o OooO'  o
       O    O            O o     o   O  o  o   O O      O
    ooOOoOo o'       `OoO' `OoO' `OoO'o Oo oOoO' `OoO'  o
                                           O
                                           o'  pbwbb


-+-+-+-+-+-+-+-+-+-+

Ping with Check-Host:

Node: rs1.node.check-host.net
        Status: OK, Latency: 0.006
        Status: OK, Latency: 0.006
        Status: OK, Latency: 0.006
        Status: OK, Latency: 0.006
Node: ru4.node.check-host.net
        Status: OK, Latency: 0.046
        Status: OK, Latency: 0.047
        Status: OK, Latency: 0.047
        Status: OK, Latency: 0.047
Node: tr1.node.check-host.net
        Status: OK, Latency: 0.054
        Status: OK, Latency: 0.053
        Status: OK, Latency: 0.053
        Status: OK, Latency: 0.052

-+-+-+-+-+-+-+-+-+-+

IP location:

country: United States(US)
region: Virginia(VA)
city: Ashburn
zip: 20149
coordinates: lat: 39.03 lon: -77.5
timezone: America/New_York

-+-+-+-+-+-+-+-+-+-+

AbuseIPdb:

IP: 8.8.8.8
Domain: google.com
hostnames: dns.google
Abuse Confidence Score: 0
IP public: True
IP version: 4
Whitelisted: True

-+-+-+-+-+-+-+-+-+-+

CriminalIP:

IP: 8.8.8.8
Malicious: False
VPN: False
Remote Access: False
Open Ports: 3
        Port: 443 tcp
        Protocol: https

        Port: 53 udp
        Protocol: dns

        Port: 53 tcp
        Protocol: dns

Vulnerabilities: 0 []

-+-+-+-+-+-+-+-+-+-+
VirusTotal analisys:

IP: 8.8.8.8
AS Owner: GOOGLE
votes:
        harmless: 189
        malicious: 29

No threats detected

-+-+-+-+-+-+-+-+-+-+

WHOIS from VirustTotal:

NetRange: 8.8.8.0 - 8.8.8.255
CIDR: 8.8.8.0/24
NetName: GOGL
NetHandle: NET-8-8-8-0-2
Parent: NET8 (NET-8-0-0-0-0)
NetType: Direct Allocation
OriginAS:
Organization: Google LLC (GOGL)
RegDate: 2023-12-28
Updated: 2023-12-28
Ref: https://rdap.arin.net/registry/ip/8.8.8.0
OrgName: Google LLC
OrgId: GOGL
Address: 1600 Amphitheatre Parkway
City: Mountain View
StateProv: CA
PostalCode: 94043
Country: US
RegDate: 2000-03-30
Updated: 2019-10-31
Comment: Please note that the recommended way to file abuse complaints are located in the following links.
Comment:
Comment: To report abuse and illegal activity: https://www.google.com/contact/
Comment:
Comment: For legal requests: http://support.google.com/legal
Comment:
Comment: Regards,
Comment: The Google Team
Ref: https://rdap.arin.net/registry/entity/GOGL
OrgTechHandle: ZG39-ARIN
OrgTechName: Google LLC
OrgTechPhone: +1-650-253-0000
OrgTechEmail: arin-contact@google.com
OrgTechRef: https://rdap.arin.net/registry/entity/ZG39-ARIN
OrgAbuseHandle: ABUSE5250-ARIN
OrgAbuseName: Abuse
OrgAbusePhone: +1-650-253-0000
OrgAbuseEmail: network-abuse@google.com
OrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE5250-ARIN


-+-+-+-+-+-+-+-+-+-+

OTX AlienVault:

IP: 8.8.8.8
Reputation: 0
Pulses: 0

-+-+-+-+-+-+-+-+-+-+

FEODO c2 tracker by abuse.ch:

Not found on the past 30 days IOCs

-+-+-+-+-+-+-+-+-+-+

ThreatFox by abuse.ch:

Your search did not yield any results

-+-+-+-+-+-+-+-+-+-+

GreyNoise:

IP: 8.8.8.8
Name: Google Public DNS
This IP is part of our RIOT project, which identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products.

-+-+-+-+-+-+-+-+-+-+

```

## Disclaimer

This tool is for educational and research purposes only. I am not responsible for any misuse of APIs or tools used in this script. Use responsibly and respect API usage limits.


---

[GitHub Repository](https://github.com/pbwbb/IPscalper) by pbwbb
