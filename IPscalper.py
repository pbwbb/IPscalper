#!usr/bin/python
import requests
import argparse
import json
import urllib3
import time


#pip install requests
#pip install argparse
#pip install json
#pip install urllib3

with open('API_keys.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        if line.startswith("VirusTotal"):
            VirusTotal_key = line.split(':')[1].strip()
        if line.startswith("AbuseIPdb"):
            AbuseIPdb_key = line.split(':')[1].strip()
        if line.startswith("OTX"):
            otx_key = line.split(':')[1].strip()
        if line.startswith("CriminalIP"):
            CriminalIP_key = line.split(':')[1].strip()
        if line.startswith("GreyNoise"):
            GreyNoise_key = line.split(':')[1].strip()

# Change API keys here
# AbuseIPdb_key = ""    
# VirusTotal_key = ""
# otx_key = ""
# CriminalIP_key


def logo():
    ascii = '''
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
    '''
    print(ascii)
    linha_separacao()
    # I used this https://manytools.org/hacker-tools/ascii-banner/ to make the logo :)

def linha_separacao():
    print("\n"+("-+" * 10))

def ip_api(IP,args):
    try:
        response = requests.get(f"http://ip-api.com/json/{IP}")
        data = response.json()
        if args.raw == True:
            print(response.text)
        elif data['status'] == "success":
            print("\nIP location:\n")
            print(f"country: {data['country']}({data['countryCode']})")
            print(f"region: {data['regionName']}({data['region']})")
            print(f"city: {data['city']}")
            print(f"zip: {data['zip']}")
            print(f"coordinates: lat: {data['lat']} lon: {data['lon']}")
            print(f"timezone: {data['timezone']}")
            linha_separacao()
        else: print(f"\nIP location:\nHTTP {response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nIP location:\n")
        print("Oops...", e)
        linha_separacao()

def vt(IP,args,VirusTotal_key):
    try:
        headers = {"x-apikey":  VirusTotal_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{IP}", headers=headers)
        data = response.json()
        if args.raw == True:
            print(response.text)
        elif response.status_code == 200:    
            analisys = data['data']['attributes']['last_analysis_results']
            detected = False
            for vendor in analisys.keys():
                if analisys[vendor]['result'] not in ["clean","unrated"]:
                    detected = True 
            if detected == True:
                print("\nVirusTotal analisys:\n")
                print(f"IP: {data['data']['id']} ")
                print(f"AS Owner: {data['data']['attributes']['as_owner']}")
                print(f"votes: \n\tharmless: {data['data']['attributes']['total_votes']['harmless']}\n\tmalicious: {data['data']['attributes']['total_votes']['malicious']}\n")
                for vendor in analisys.keys():
                    if analisys[vendor]['result'] not in ["clean","unrated"]:
                        print(f"Vendor: {analisys[vendor]['engine_name']}")
                        print(f"Category: {analisys[vendor]['category']}")
                        print(f"Result: {analisys[vendor]['result']}")
            elif detected == False:
                print("VirusTotal analisys:\n")
                print(f"IP: {data['data']['id']} ")
                print(f"AS Owner: {data['data']['attributes']['as_owner']}")
                print(f"votes: \n\tharmless: {data['data']['attributes']['total_votes']['harmless']}\n\tmalicious: {data['data']['attributes']['total_votes']['malicious']}\n")
                print("No threats detected")
            linha_separacao()
            print("\nWHOIS from VirustTotal: \n")
            print(f"{data['data']['attributes']['whois']}")
            linha_separacao()
        elif response.status_code == 401:
                print("\nVirusTotal:\n")
                print(f"Ivalid API key\nMessage: {data['error']['message']}")
                linha_separacao()
        else: print(f"\nVirusTotal:\nHTTP {response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nVirusTotal:\n")
        print("Oops...", e)
        linha_separacao()

def abuseIP(IP,args,AbuseIPdb_key):
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': IP,'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json','Key': AbuseIPdb_key}
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        data = response.json()
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            print("\nAbuseIPdb:\n")
            print(f"IP: {data['data']['ipAddress']}")
            print(f"Domain: {data['data']['domain']}")
            for hostname in data['data']['hostnames']:
                print(f"hostnames: {hostname}")
            print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
            print(f"IP public: {data['data']['isPublic']}")
            print(f"IP version: {data['data']['ipVersion']}")
            print(f"Whitelisted: {data['data']['isWhitelisted']}")
            linha_separacao()
        elif response.status_code == 401:
                print("\nAbuseIPdb:\n")
                print(f"Ivalid API key\nMessage: {data['errors']}")
                linha_separacao()
        else: print(f"\nAbuseIPdb:\nHTTP {response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nAbuseIPdb:\n")
        print("Oops...", e)
        linha_separacao() 

def otx(IP,args,otx_key): 
    try:
        url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{IP}/general'
        headers = {'X-OTX-API-KEY' : otx_key}
        response = requests.request(method='GET', url=url, headers=headers)
        data = response.json()
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            print("\nOTX AlienVault:\n")
            print(f"IP: {data['indicator']}")
            print(f"Reputation: {data['reputation']}")
            print(f"Pulses: {data['pulse_info']['count']}")
            for pulse in data['pulse_info']['pulses']:
                print(f"Name: {pulse['name']}")
                print("tags:")
                for i in pulse['tags']: print("\t",i)
            if len(data['pulse_info']['related']['alienvault']['malware_families']) > 0:
                print("Malware families(alienvault):")
                for i in data['pulse_info']['related']['alienvault']['malware_families']: print("\t",i)
            if len(data['pulse_info']['related']['other']['malware_families']) > 0:
                print("Malware families(other):")
                for i in data['pulse_info']['related']['other']['malware_families']: print("\t",i)    
            linha_separacao()
        elif response.status_code == 401:
                print("\nOTX AlienVault:\n")
                print(f"Ivalid API key\n")
                linha_separacao()
        else: print(f"\nOTX AlienVault:\nHTTP {response.status_code}\n{response.text}")          
    except requests.exceptions.RequestException as e:
        print(f"\nOTX AlienVault:\n")
        print("Oops...", e)
        linha_separacao()

def crimninalip(IP,args,CriminalIP_key):
    try:
        url = (f'https://api.criminalip.io/v1/feature/ip/malicious-info?ip={IP}')
        headers = {'x-api-key': CriminalIP_key}
        response = requests.request(method='GET', url=url, headers=headers)
        data = response.json()
        if args.raw == True: 
            print(response.text)
        elif data['status'] == 200:       
            print(f"\nCriminalIP:\n")
            print(f"IP: {data['ip']}")
            print(f"Malicious: {data['is_malicious']}")
            print(f"VPN: {data['is_vpn']}")
            print(f"Remote Access: {data['can_remote_access']}")
            print(f"Open Ports: {data['current_opened_port']['count']}")
            if data['current_opened_port']['count'] > 0:
                for i in data['current_opened_port']['data']:
                    print(f"\tPort: {i['port']} {i['socket_type']}")
                    print(f"\tProtocol: {i['protocol']}\n")
            print(f"Vulnerabilities: {data['vulnerability']['count']} {data['vulnerability']['data']}")
            linha_separacao()
        elif data['status'] == 500:
            print("\nCriminalIP:\n")
            print(f"Ivalid API key\nmessage:{data['message']}\nStatus: {data['status']}")
            linha_separacao()
        else: print(f"\nCriminalIP:\nHTTP {data['status']}\n{response.text}"), linha_separacao() 
    except requests.exceptions.RequestException as e:
        print(f"\nCriminalIP:\n")
        print("Oops...", e)
        linha_separacao()

def C2(IP,args):
    try:
        response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        data = response.json()
        detected = False
        if response.status_code == 200:
            for c2 in data:
                if IP in c2['ip_address']:
                    detected = True
            if detected == True:
                for c2 in data:
                    if args.raw ==True: 
                        if IP in c2['ip_address']:
                            print(c2)
                        break
                    else:
                        if IP in c2['ip_address']:
                            print(f"\nFEODO C2 tracker by abuse.ch:\n")
                            print(f"IP: {c2['ip_address']}")
                            print(f"Malware: {c2['malware']}")
                            print(f"Port: {c2['port']}")
                            print(f"Status: {c2['status']}")
                            print(f"Hostname: {c2['hostname']}")
                            print(f"Country: {c2['country']}")
                            print(f"Last online: {c2['last_online']}") 
                            linha_separacao()    
            if detected == False:
                if args.raw == False:    
                    print(f"\nFEODO c2 tracker by abuse.ch:\n")
                    print(f"Not found on the past 30 days IOCs") 
                    linha_separacao()
        else: print(f"\nFEODO C2 tracker by abuse.ch:\nHTTP{response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nFEODO C2 tracker by abuse.ch:\n")
        print("Oops...", e)
        linha_separacao()

def threatfox(IP,args):
    try:
        
        pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
        query = {
            'query':            'search_ioc',
            'search_term':      IP
        }
        json_query = json.dumps(query)
        response = pool.request("POST", "/api/v1/", body=json_query)
        data = response.json()
        if args.raw == True: 
            print(data)
        elif data['query_status'] == 'no_result':
            print("\nThreatFox by abuse.ch:\n")
            print(data['data'])
            linha_separacao()    
        elif data['query_status'] == 'ok':
            print("\nThreatFox by abuse.ch:\n")
            print(f"ID: {data['data'][0]['id']}")
            print(f"IoC: {data['data'][0]['ioc']}")
            print(f"Threat type: {data['data'][0]['threat_type']}")
            print(f"Malware: {data['data'][0]['malware_printable']} ({data['data'][0]['malware']})")
            print(f"Confidence: {data['data'][0]['confidence_level']}")
            print(f"First seen: {data['data'][0]['first_seen']}")
            print(f"Last seen: {data['data'][0]['last_seen']}")
            linha_separacao() 
        else: print(f"\nThreatFox by abuse.ch:\nHTTP {response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nThreatFox by abuse.ch:\n")
        print("Oops...", e)
        linha_separacao()

def greynoise(IP,args,Greynoise_key):
    try:
        url = (f'https://api.greynoise.io/v3/community/{IP}')
        headers = {'key': Greynoise_key}
        response = requests.request(method='GET', url=url, headers=headers)
        data = response.json()
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            print("\nGreyNoise:\n")
            print(f"IP: {data['ip']}")
            print(f"Name: {data['name']}") 
            if data['riot'] == True: print("This IP is part of our RIOT project, which identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products.")
            elif data['noise'] == True: print(f"Ths IP has been seen scanning the internet\nLast seen: {data['last_seen']}")    
            linha_separacao()
        elif response.status_code == 401:
            print("\nGreyNoise:\n")
            print(f"Ivalid API key\n")
            linha_separacao()
        elif response.status_code == 404:
            print("\nGreyNoise:\n")
            print(f"IP: {data['ip']}")
            print(data['message'])    
            linha_separacao()    
        else: print(f"\nOTX AlienVault:\nHTTP {response.status_code}\n{response.text}")       
    except requests.exceptions.RequestException as e:
        print(f"\nGreyNoise:\n")
        print("Oops...", e)
        linha_separacao()

def ping(IP,args):
    try:
        url_request = (f'https://check-host.net/check-ping?host={IP}&max_nodes=3')
        headers = {'Accept' : 'application/json'}
        response_request = requests.request(method='GET', url=url_request, headers=headers)
        data_request = response_request.json()
        request_id = data_request['request_id']
        url = (f"https://check-host.net/check-result/{request_id}")
        time.sleep(2)
        response = requests.request(method='GET', url=url, headers=headers)
        data = response.json()
        if args.raw == True: 
            print(data_request)
            print(data)
        elif response.status_code == 200:
            print(f"\nPing with Check-Host:\n")
            for node,result in data.items():
                print("Node:",node)
                for result_set in result:
                    if result_set[0] == None:
                            print("\tUnknown host")
                    else:
                        for status in result_set:
                            print(f"\tStatus: {status[0]}, Latency: {status[1]:.3f}") 
            linha_separacao()       
        else: print(f"\n:Ping with Check-host\nHTTP {response.status_code}\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\nPing with Check-host:\n")
        print("Oops...", e)
        linha_separacao()

def main(): 
    description = (f"A tool for finding open source information about IP addresses\n All tools used on this script are free, although API keys are necessary for some of them. To get the keys you only need to create an account.\nBe mindiful of API limits.\nI am not responsible for any misuse of APIs or tools on this script")
    parser=argparse.ArgumentParser(prog="IPscalper",description=description,epilog="https://github.com/pbwbb/Projects/tree/main/IPscalper by Pedro Webber")
    parser.add_argument("IP", help="IP address that is going to be searched")
    parser.add_argument("-all", required=False,  action="store_true", help="Uses all tools")
    # parser.add_argument("-v","--verbose", required=False,  action="store_true", help="Verbose output")
    parser.add_argument("-geo","--location", required=False,  action="store_true", help="Uses IP-api to get IP location (no key needed)") #IP-API no key
    parser.add_argument("-raw", required=False, action="store_true", help="Displays raw json output")
    parser.add_argument("-ping", required=False, action="store_true", help="Uses check-host.net to ping the IP form multiple hosts (no key needed)")
    parser.add_argument("-vt","--VirusTotal", required=False,  action="store_true", help="Uses VirusTotal API for info (key required -> edit API_keys.txt file or uncomment lines)")
    parser.add_argument("-abuse","--AbuseIPdb", required=False,  action="store_true", help="Uses AbuseIPdb API for info (key required -> edit API_keys.txt file or uncomment lines)")  
    parser.add_argument("-otx","--AlienVault", required=False,  action="store_true", help="Uses OTX AlienVault API for info (key required -> edit API_keys.txt file or uncomment lines)") # alienvault
    parser.add_argument("-showkeys", required=False,  action="store_true", help="display API keys") # display API keys
    parser.add_argument("-criminalip", required=False,  action="store_true", help="Uses CriminalIP api for info (key required -> edit API_keys.txt file or uncomment lines)")
    parser.add_argument("-c2","--Feodo", required=False,  action="store_true", help="Checks if IP is in Abuse.ch Feodo tracker last 30 days C2 IoCs (no key needed)") #https://feodotracker.abuse.ch
    parser.add_argument("-threatfox", required=False,  action="store_true", help="Uses abuse.ch ThreatFox API for info (no key needed)")
    parser.add_argument("-gn","--greynoise", required=False,  action="store_true", help="Uses GreyNoise API for info (key required -> edit API_keys.txt file or uncomment lines)")
    parser.add_argument("-nokey", required=False,  action="store_true", help="Only uses tools that do not require an API key")
    parser.add_argument("-nobanner", required=False,  action="store_true", help="Do not display banner")
    args=parser.parse_args()
    
    IP = args.IP

    if args.nobanner == False:
        logo()
    if args.all == True:
        ping(IP,args)
        ip_api(IP,args)
        abuseIP(IP,args,AbuseIPdb_key)
        crimninalip(IP,args,CriminalIP_key)
        vt(IP,args,VirusTotal_key)
        otx(IP,args,otx_key) 
        C2(IP,args) 
        threatfox(IP,args)
        greynoise(IP,args,GreyNoise_key)      
    else:
        if args.showkeys == True:
            print("API keys:\n")
            print("VirusTotal: ", VirusTotal_key)
            print("AbuseIPdb: ", AbuseIPdb_key)
            print("OTX AlienVault: ", otx_key)
            print("CriminalIP: ", CriminalIP_key)
        if args.ping == True:
            ping(IP,args)
        if args.nokey == True:
            ip_api(IP,args)
            C2(IP,args)
            threatfox(IP,args)
        if args.location == True:
            ip_api(IP,args)
        if args.AbuseIPdb == True:
            abuseIP(IP,args,AbuseIPdb_key)
        if args.criminalip ==  True:
            crimninalip(IP,args,CriminalIP_key)
        if args.VirusTotal == True:
            vt(IP,args,VirusTotal_key)
        if args.AlienVault == True:
            otx(IP,args,otx_key)
        if args.Feodo == True:
            C2(IP,args)
        if args.threatfox == True:
            threatfox(IP,args)
        if args.greynoise == True:
            greynoise(IP,args,GreyNoise_key)
        if not any(vars(args).values()):
            ip_api(IP,args)
            C2(IP,args)
            threatfox(IP,args)

if __name__ == "__main__":
    main()
