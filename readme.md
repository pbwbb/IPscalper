![image](https://github.com/pbwbb/IPscalper/assets/151950149/57ae9ada-ea11-427f-b200-cd51c74817c1)


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
                                           o'  by Pedro Webber                
    
```
## Description

IPscalper is a tool for gathering open-source information about IP addresses. It integrates various APIs to retrieve data such as geographical location, reputation, IoCs and open ports.

You can use this Script to get parsed or raw results from these tools:
* VirusTotal  
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
usage: IPscalper [-h] [-all] [-geo] [-raw] [-vt] [-abuse] [-otx] [-showkeys] [-criminalip] [-c2] [-threatfox] [-gn] [-nokey] IP

A tool for finding open source information about IP addresses 
All tools used on this script are free, although API keys are necessary for some of them. To get the keys you only need to create an       
account. 
Be mindiful of API limits. 
I am not responsible for any misuse of APIs or tools on this script

positional arguments:
  IP                   IP address that is going to be searched

options:
  -h, --help           show this help message and exit
  -all                 Uses all tools
  -geo, --location     Uses IP-api to get IP location (no key needed)
  -raw                 Displays raw json output
  -vt, --VirusTotal    Uses VirusTotal API for info (key required -> edit API_keys.txt file or uncomment lines)
  -abuse, --AbuseIPdb  Uses AbuseIPdb API for info (key required -> edit API_keys.txt file or uncomment lines)
  -otx, --AlienVault   Uses OTX AlienVault API for info (key required -> edit API_keys.txt file or uncomment lines)
  -showkeys            display API keys
  -criminalip          Uses CriminalIP api for info (key required -> edit API_keys.txt file or uncomment lines)
  -c2, --Feodo         Checks if IP is in Abuse.ch Feodo tracker last 30 days C2 IoCs (no key needed)
  -threatfox           Uses abuse.ch ThreatFox API for info (no key needed)
  -gn, --greynoise     Uses GreyNoise API for info (key required -> edit API_keys.txt file or uncomment lines)
  -nokey               Only uses tools that do not require an API key

https://github.com/pbwbb/Projects/tree/main/IPscalper by Pedro Webber
```
## Example output

```
python IPscalper.py -all 8.8.8.8

    ooOoOOo OooOOo.                      o                    
       O    O     `O                    O                     
       o    o      O                    o                     
       O    O     .o                    O                     
       o    oOooOO'  .oOo  .oOo  .oOoO' o  .oOo. .oOo. `OoOo. 
       O    o        `Ooo. O     O   o  O  O   o OooO'  o     
       O    O            O o     o   O  o  o   O O      O     
    ooOOoOo o'       `OoO' `OoO' `OoO'o Oo oOoO' `OoO'  o     
                                           O                  
                                           o'  by Pedro Webber                
    

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
	harmless: 186
	malicious: 29
Vendor: ArcSight Threat Intelligence
Category: malicious
Result: malware

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

GreyNoise: 8.8.8.8
Name: Google Public DNS
This IP is part of our RIOT project, which identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products.

-+-+-+-+-+-+-+-+-+-+

```

## Disclaimer

I am not responsible for any misuse of APIs or tools used in this script. Use responsibly and respect API usage limits.


---

[GitHub Repository](https://github.com/pedrowebber/IPscalper) by Pedro Webber
