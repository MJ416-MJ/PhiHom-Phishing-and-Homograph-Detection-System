

from rapidfuzz import fuzz,process
import json
import os
from urllib.parse import urlparse
import re
import time
start_time = time.time()
def get_url_components(url_string):
    if(url_string is None or url_string == ""):
        raise ValueError("URL string is empty or None")
    parsed_url = urlparse(url_string)
    url_scheme = parsed_url.scheme
    url_netloc = parsed_url.netloc
    url_path = parsed_url.path
    url_query = parsed_url.query
    url_params = parsed_url.params
    url_hostname = parsed_url.hostname
    url_components = {'scheme':url_scheme,
                      'netloc':url_netloc,
                      'path':url_path,
                      'query':url_query,
                      'params':url_params,
                      'hostname':url_hostname}
    return url_components
def check_url_length(url_string):
    result = get_url_components(url_string)
    if result['hostname'] and '.'.join(result['hostname'].split('.')[-2:]) in url_shorteners:
            return 0
    url_length = len(url_string)
    if(url_length <=50):
        return -1
    elif(url_length>50 and url_length<70):
        return 1
    else:
        return 2
    
def check_ip_address(url_string):
    ip_pattern = re.search(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', url_string)
    if (ip_pattern is None):
        return 0,0
    else:
        return 2,ip_pattern.group(0)
    
def check_at_in_url(url_string):
    if ('@' in url_string):
        return 2
    else:
        return 0
def check_hyphen_in_url(url_string):
    result = get_url_components(url_string)
    hyphen_count = result['netloc'].count('-')
    if('-' in result['netloc']):
        if(hyphen_count>2):
            return 2,hyphen_count
        elif (hyphen_count>=1):
            return 1,hyphen_count
        else:
            return 0,0
    else:
        return 0,0
    

def check_suspicious_tld(url_string):
    result = get_url_components(url_string)
    if result['hostname'] is None:
        return 0
    x = result['hostname'].split('.')
    tld = '.'+ x[-1]
    file_path = os.path.join(os.path.dirname(__file__),'data','tlds_scoring.json')
    with open(file_path, 'r') as f:
        unknown_tlds = json.load(f)
    if tld in unknown_tlds["high_risk"]:
        return 2,tld
    elif tld in unknown_tlds["medium_risk"]:
        return 1,tld
    elif tld in unknown_tlds["common_neutral"]:
        return 0,""
    else:
        return 1,tld

def compiled_pattern_keyword(keywords):
    return{
        kw:re.compile(
            r'(^|[./-])'+ re.escape(kw).replace(r'\.', '[.-]')+r'([./-]|$)'
            )
        for kw in keywords
    }

keywords_path= os.path.join(os.path.dirname(__file__),'data','suspicious_keywords.json')
with open(keywords_path, 'r') as f:
    suspicious_keywords = json.load(f)

high_risk = compiled_pattern_keyword(suspicious_keywords["high_risk"])
medium_risk = compiled_pattern_keyword(suspicious_keywords["medium_risk"])

def check_suspicious_keyword(url_string):
    result = get_url_components(url_string)
    x = result['hostname']
    y = result['path']
    z = result['query']
    hostname_hit = 0
    path_queryhit = 0
    score = 0
    
    
    if x is None:
        x = ""
    if y is None:
        y = ""
    if z is None:
        z = ""
    matched_keywords = []
    
    for kw, pattern in high_risk.items():
        hostname_pattern = pattern.search(x)
        path_pattern = pattern.search(y)
        query_pattern = pattern.search(z)
        
        if hostname_pattern is not None:
            hostname_hit+=2
            matched_keywords.append(kw)
        if path_pattern is not None or query_pattern is not None:
            path_queryhit+=1
            matched_keywords.append(kw)
    for kw , pattern in medium_risk.items():
        hostname_pattern = pattern.search(x)
        path_pattern = pattern.search(y)
        query_pattern = pattern.search(z)
        
        if hostname_pattern is not None:
            hostname_hit+=1
            matched_keywords.append(kw)
        if path_pattern is not None or query_pattern is not None:
            path_queryhit+=1
            matched_keywords.append(kw)
            
    
    if (hostname_hit >= 2):
        score += 2
    elif(hostname_hit==1):
        score+= 1
    
    score += min(path_queryhit,1)
    
    
    if (score >=2):
        return 2,matched_keywords
    elif(score == 1):
        return 1,matched_keywords
    else:
        return 0,""
file_path_shorteners = os.path.join(os.path.dirname(__file__),'data','url_shorteners.txt')
with open(file_path_shorteners, 'r') as f:
        url_shorteners = f.read().splitlines()
def check_url_shortener(url_string):
    result = get_url_components(url_string)
    
    if result['hostname'] in url_shorteners:
        return 2,result['hostname']
    return 0,0
def check_url_subdomains(url_string):
    result = get_url_components(url_string)
    if result['hostname'] is None:
        return 0,0
    parts = result['hostname'].split('.')
    subdomains = parts[:-2]
    if result['hostname'].count('.')>=3:
        return 2,subdomains
    elif result['hostname'].count('.')==2:
        return 0,subdomains
    return 0,""
def check_scheme(url_string):
    result = get_url_components(url_string)
    if result['scheme'] is None:
        return 2,result['scheme']
    if result['scheme'] == 'http':
        return 1,result['scheme']
    if result['scheme'] == 'https':
        return 0,[]
    return 2,result['scheme']



file_path_domains = os.path.join(os.path.dirname(__file__), 'data', 'legitimate_domains.csv')
with open(file_path_domains, 'r') as f:
        legitimate_domains = [line.split(',')[1].strip() for line in f.read().splitlines() if ',' in line]
      
def normalize_domain(s):
    table = str.maketrans('013457', 'oleast')
    return s.translate(table)

def check_domain_similarity(url_string):
    result = get_url_components(url_string)
    if result['hostname'] is None:
        return 0,""
    parts = result ['hostname'].split('.')
    domain = '.'.join(parts[-2:])
    if domain in url_shorteners:
        return 0,""
    
    subdomain = '.'.join(parts[:-2])
    normalized_domain = normalize_domain(domain)
    NOISE_WORDS = {
    'http', 'https', 'www', 'secure', 'login', 
    'verify', 'account', 'update', 'portal', 
    'totally', 'total', 'local', 'my', 'xn'
    }
    if '-' in domain:
        base_name = domain.split('-')[0].split('.')[0]
        if len(base_name) >= 5 and base_name not in NOISE_WORDS:
            tld_only = '.' + domain.split('.')[-1]
            raw_query = base_name + tld_only
            normalized_query = normalize_domain(base_name) + tld_only
        else:
            normalized_query = normalized_domain
    else:
        normalized_query = normalized_domain

    domain_match = process.extractOne(normalized_query, legitimate_domains, scorer=fuzz.ratio)
    
    best_match = None
    best_ratio = 0

    if domain_match is not None:
        matched_domain, ratio, _ = domain_match
        best_match = matched_domain
        best_ratio = ratio

    if subdomain:
        normalized_subdomain = normalize_domain(subdomain)
        if '.' in normalized_subdomain:
            normalized_subdomain_base = normalized_subdomain.split('.')[0]
            possible_tld =normalized_subdomain.split('.')[1]
            normalized_subdomain =  normalized_subdomain_base+'.'+possible_tld
        subdomain_match = process.extractOne(normalized_subdomain, legitimate_domains, scorer=fuzz.ratio)
        if subdomain_match is not None:
            matched_domain, ratio, _ = subdomain_match  
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = matched_domain  
        
    
    
    if best_match is None:
        return 0, ""
    final_ratio = fuzz.ratio(result['hostname'],best_match) 

    highest_ratio = final_ratio/100
    
    if highest_ratio == 1.0 and best_match == domain:
        return -1, best_match
    elif highest_ratio == 1.0:
        return 2, best_match
    elif highest_ratio >=0.8 and highest_ratio < 1.0:
        return 2,best_match
    elif highest_ratio >= 0.2 and highest_ratio < 0.8:
        return 1,best_match
    elif highest_ratio < 0.2:
        return 0,""

     

def analyse_url(url_string):
    score = 0
    indicators = []
    length_score = (check_url_length(url_string))
    score+=length_score
    if(length_score>0):
        indicators.append("URL is longer than 50 characters:"+ str(len(url_string)))
    ip_score,extracted_ip =(check_ip_address(url_string))
    score+=ip_score
    if(ip_score>0):
        indicators.append("ip address detected: "+str(extracted_ip))
    
    at_in_url_score =check_at_in_url(url_string)
    score+= at_in_url_score
    if(at_in_url_score>0):
        indicators.append("@ symbol detected in url")
    hyphen_score, hyphen_count = check_hyphen_in_url(url_string)
    score+=hyphen_score
    if(hyphen_score>0):
        indicators.append("Hyphen detected:"+str(hyphen_count))
    keyword_score,word_list = check_suspicious_keyword(url_string)
    score+=keyword_score
    counter = len(word_list)
    if(keyword_score>0):
        if(counter>1):
            indicators.append("Keywords detected: "+ str(set(word_list)))
        else:
            indicators.append("Keyword detected: "+ str(set(word_list)))
    url_shortener_score, host_shortener= check_url_shortener(url_string)
    score+=url_shortener_score
    if(url_shortener_score>0):
        indicators.append("Url shortener detected: "+ str(host_shortener))
    
    subdomain_score,subdomain = check_url_subdomains(url_string)
    score += subdomain_score
    if(subdomain_score>0):
        indicators.append("More than 2 subdomains found: "+ str(subdomain))
    
    scheme_score,scheme = check_scheme(url_string)
    score+= scheme_score
    if(scheme_score>0):
        indicators.append("Insecure scheme detected: "+ str(scheme))
        
    tld_score, tld = check_suspicious_tld(url_string)
    score+=tld_score
    if(tld_score>0):
        indicators.append("Suspicious top level domain found: "+ str(tld))
    
    
    similarity_scorer,close_match=check_domain_similarity(url_string)
    score+=similarity_scorer
    if(similarity_scorer>0):
        indicators.append("The domain closely matches "+ str(close_match))
    
    
    if (score>=4):
        verdict="Dangerous"
    elif (score>=2):
        verdict= "Suspicious"
    elif (score>0):
        verdict= "Unknown website, Be cautious"
    else:
        verdict ="Legitimate" 
  
    
    return json.dumps({
    "score": score,
    "verdict": verdict,
    "indicators": indicators 
    },indent=2)
            


