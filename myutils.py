#!/usr/bin/python3
import re
import math
import collections
from difflib import get_close_matches


special_characters = [':', '=', ",", ';', '[', ']', '{', '}', '\\', '|', '?', '/']
split_characters = [".", "-", "+", "_", "%2D", "%2d", "%2B", "%2b", "%5f", "%5F", "%2e", "%2E"]
digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']

def estimate_shannon_entropy(dna_sequence):
    m = len(dna_sequence)
    bases = collections.Counter([tmp_base for tmp_base in dna_sequence])
 
    shannon_entropy_value = 0
    for base in bases:
        # number of residues
        n_i = bases[base]
        # n_i (# residues type i) / M (# residues in column)
        p_i = n_i / float(m)
        entropy_i = p_i * (math.log(p_i, 2))
        shannon_entropy_value += entropy_i
 
    return shannon_entropy_value * -1

def has_match(list: list, string: str, limit: float):
    return get_close_matches(string, list, 1, limit)

def clear_endlines(list: list):
    for i in range(len(list)):
        if list[i][-1] == '\n':
            list[i] = list[i][:-1]

def get_directory(url: str, file: str):
    domain = url.split('/')[0]
    if not len(url) > len(domain) + 1: 
        return

    if file:
        return list(filter(lambda item: item != '', url[len(domain) + 1: url.find(file) - 1].split('/')))
    
    search_string = url[len(domain) + 1:]
    if url.__contains__('?'):
        search_string = url[len(domain) + 1: url.find('?')]
    return list(filter(lambda item: item != '', search_string.split('/')))

def get_params(queryString: str, clean_url: bool):
    if not queryString:
        return

    separator = (("&amp;", "&") [queryString.find("&amp;") == -1], '/') [clean_url]
    if not clean_url and queryString.find("&") == -1:
        separator = ';'   
    params = queryString.split(separator)
    params = list(filter(lambda item: item != '', params))
    if not clean_url:
        for i in range(0, len(params)):
            if not params[i].__contains__('='):
                params[i] = params[i] + '='

    return params 

def points_nr(string: str):
    filter = re.match(r"(.*?)(?=[/?])|(.*)", string).group(0)
    stripped = filter.replace('.', '')
    if stripped.isdigit():
        return 0
    return filter.count('.')

def get_file(url: str):
    split = list(filter(lambda item: item != '', url.split('/')))
    points = list(map(points_nr, split))
    elements = len(split)
    if elements == 1:
        return None, False, False, None

    if points[-1] == 0:
        index = split[-1].find('?')
        if index != -1:
            return None, True, False, split[-1][index + 1:]
            

    url_length = len(url)
    file, cursor = None, 0
    for i in range(len(split[0]) + url.find(split[0]) + 1, url_length - 1):
        if cursor < elements - 1 and url[i: i + len(split[cursor + 1])] == split[cursor + 1]:
            cursor += 1
        if cursor > 0 and split[cursor][0] != '.' and points[cursor] == 1 and not split[cursor].__contains__('@'):
            file = re.match(r"(.*?)(?=[/?])|(.*)", split[cursor]).group(0)
            break

    has_params, clean_url, query_string = False, False, None
    if not file and not any(map(split[-1].__contains__, ['?', '/'])):
        return file, has_params, clean_url, query_string

    index = None
    if file:
        index = url.find(file) + len(file)
    else:
        index = url.find(split[-1])    
    if index < url_length:
        query_begin_chr = url[index]
        if query_begin_chr == "?":
            has_params = True
        elif query_begin_chr == "/":
            has_params = True
            clean_url = True

    if index + 1 < url_length:
        query_string = url[index + 1:]

    return file, has_params, clean_url, query_string

def count_digits(string: str):
    digits = 0
    for i in range(0, len(string) - 1):
        digits += (0, 1) [string[i].isnumeric()]
    return digits