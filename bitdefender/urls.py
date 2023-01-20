#!/usr/bin/python3
from myutils import clear_endlines, estimate_shannon_entropy
from malware import is_malware
from phishing import is_phishing

urls = open("./data/urls/urls.in", "r").readlines()
database = open("./data/urls/domains_database", "r").readlines()
safe_domains_r = open("data.txt", "r").readlines()
output_file = open("urls-predictions.out", "w")

#wrong_urls = open("wrong-urls.out", "w")
#check = open("./tasks/my_av/tests/00-my_av/00-my_av.ref").readlines()
#ref = open("./data/urls/urls_classes", "r").readlines()

clear_endlines(database)
clear_endlines(safe_domains_r)
safe_domains = set(safe_domains_r)

accepted_protocols = set(["http", "https"])

def known_safe(domain: str):
    if domain in safe_domains:
        return True

def known_bad(domain: str):
    for i in range(len(database)):
        if domain == database[i] or database[i] in domain:
            return True    

def check_protocol(url: str):
    protocol = url.split("://")[0]
    if not (protocol == url):
        if not protocol in accepted_protocols:
            return True
        return False

def weird_entropy(domain: str):
    estimate = estimate_shannon_entropy(domain)
    if estimate < 2.1 or estimate > 4.5:
        return 1

def valid_domain(domain: str):
    split = domain.split('.')
    if len(split) > 2 and (split[:-2] in ['msn', 'go'] or split[:-3] in ['msn', 'go']):
        return 1

    for safe_domain in safe_domains_r:
        length = len(safe_domain.split('.'))
        domain_len = len(safe_domain)
        if len(split) >= length and len(domain) > domain_len and domain[-domain_len-1:] == '.' + safe_domain:
            return 1

def validate_url(url: str):
    if url[0] == "'":
        return 0, "not_a_link"

    protocol_result = check_protocol(url)
    if protocol_result:
        return 1, "bad_protocol"
    if protocol_result == False:
        protocol = url.split("://")[0]
        url = url[len(protocol) + 3:]
    
    if url.__contains__("http"):
        return 0, "http_in_url"

    domain = url.split('/')[0]
    if known_safe(domain):
        return 0, "known_safe"

    if valid_domain(domain):
        return 0, "valid_domain"

    if known_bad(domain):
        return 1, "known_bad"  

    if weird_entropy(domain):
        return 1, "weird_entropy"

    malware, reason = is_malware(url)
    if reason == "SAFE":
        return 0, ".htm_file"
    if malware:
        return 1, "malware: " + reason

    phishing, reason = is_phishing(url)
    if phishing:
        return 1, "phishing: " + reason

    return 0, "no_criteria_matches"        

def check_urls():
    #count = 0
    for i in range(len(urls)):
        if urls[i][-1] == '\n':
            urls[i] = urls[i][:-1]
        
        verdict, reason = validate_url(urls[i])
        output_file.write(str(verdict) + "\n")
        #if not (str(verdict) == check[i][0]):
            #count += 1
            #wrong_urls.write(urls[i] + ", " + ref[i][:-1] + ", " + reason + "\n") 
        
    #print(count, "wrong urls")
    output_file.close()   