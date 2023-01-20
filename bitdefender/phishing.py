#!/usr/bin/python3
import re
from myutils import has_match, count_digits
from myutils import clear_endlines, get_directory, get_file
from myutils import special_characters, split_characters, digits

safe_domains_r = open("data.txt", "r").readlines()
tlds_r = open("data3.txt", "r").readlines()
clear_endlines(safe_domains_r)
clear_endlines(tlds_r)
safe_domains = set(safe_domains_r)
tlds = set(tlds_r)

SIMILARITY_PROCENT = 0.9
safe_ports = [":21", ":22", ":23", ":25", ":53", ":80", ":443", ":445", ":1433", ":1521", ":3306", ":3389", ":4201"]
hex_ipv4_regex = re.compile(r'.*(0x[0-9a-fA-F]{1,2}\.){3}(0x[0-9a-fA-F]{1,2}).*')
ipv4_regex = re.compile(r'.*((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]).*')

url_checks = ["contains_hex_ip", "url_in_url", "filter_dirs"]
domain_checks = [
    "digits_in_domain", "misspelled_domain", "uses_nonstd_port", "bad_tld",
    "weird_subdomain", "too_many_components", "just_domain", "hyphen_subdomain",
    "subdomain_digits"
]
directory_checks = ["too_long_dirs"]

def contains_hex_ip(url: str):
    if hex_ipv4_regex.match(url) or ipv4_regex.match(url):
        return "contains_IP"

def url_in_url(url: str):
    split = url.split("/")
    if len(split) < 3:
        return
    
    rest_url = "/".join(str(x) for x in split[1: len(split) - 2])
    question_mark = rest_url.find("?")
    points_in_dir = (rest_url.count("."), rest_url[:question_mark - 1].count(".")) [question_mark != -1]
    if points_in_dir > 3:
        return "url_in_url"             

def filter_dirs(url: str):
    if url.count('/') > 10:
        return "big_path"

def digits_in_domain(domain: str, url: str):
    digits = 0
    for i in range(len(domain)):
        digits += (0, 1) [domain[i].isnumeric() and (i > 0 and not domain[i - 1].isnumeric()) and (i < len(domain) - 1 and not domain[i - 1].isnumeric())]
    if digits >= 0.1 * len(domain) and digits > 1:
        return "digits_in_domain"

def misspelled_domain(domain: str, url: str):
    match = has_match(safe_domains, domain, SIMILARITY_PROCENT)
    if match and not match[0] in domain:
        return "too_similar " + str(match) + " " + domain

def too_many_components(domain: str, url: str):
    if domain.count(".") > 4:
        return " too_many_components"   

def just_domain(domain: str, url: str):
    if domain == url:
        return "plain_url"

def weird_subdomain(domain: str, url: str) :
    subdomain = domain.split(".")[0]
    if len(subdomain) > 3 and subdomain.__contains__("ww") and not (subdomain == "www"):
        return "weird_subdomain"

    components = domain.count('.')
    if not components > 2:
        return

    if any(map(subdomain.__contains__, digits)) or any(map(subdomain.__contains__, special_characters)):
        return " weird_subdomain"

def uses_nonstd_port(domain: str, url: str):
    if not domain.__contains__(":"):
        return
    if not any(map(domain.__contains__, safe_ports)):
        return "nonstd_port"

def hyphen_subdomain(domain: str, url: str):
    subdomain = domain.split('.')[0]
    if len(domain.split('.')) > 2 and subdomain.count('-') > 2:
        return "hyphen_subdomain"

def bad_tld(domain: str, url: str):
    tld = domain.split('.')[-1]
    if tld in tlds:
        return "bad_tlds"

def subdomain_digits(domain: str, url: str):
    subdomain = domain.split('.')[0]
    if len(domain.split('.')) < 3:
        return
    digits = count_digits(subdomain)
    if digits > 1 and digits >= .5 * len(subdomain):
        return "digits_subdomain"

def too_long_dirs(directories: list):
    if not directories:
        return

    for directory in directories:
        if len(directory) > 32 and not any(map(directory.__contains__, split_characters)):
            return "too_long_dir"  

def run_checks(checks, **kwargs):
    response, score = "", 0    
    for check in checks:
        result = globals()[check](**kwargs)
        if result:
            if result == 'SAFE':
                response, score = "SAFE", -69
                return response, score
            response, score = result + " + " + response, score + 1

    return response, score

def is_phishing(url: str):
    full_domain = url.split("/")[0]
    file, has_params, clean_url, query_string = get_file(url)
    directory = get_directory(url, file)

    url_response, url_score = run_checks(url_checks, url = url)
    domain_response, domain_score = run_checks(domain_checks, domain = full_domain, url = url)
    directory_response, directory_score = run_checks(directory_checks, directories = directory)

    response = url_response + ' ' + domain_response + ' ' + directory_response
    response = response.replace(' ', '')
    score = url_score + domain_score + directory_score
    
    return ((False, ''), (True, str(response) + str(score))) [score >= 1]  