import homograph
from homograph import homographchecker,confusables
from rapidfuzz import fuzz,process
import json
import suggestion
import os
from urllib.parse import urlparse
import re
import sys

def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(__file__)
def is_valid_url(url_string):
    pattern = re.compile(r'^https?://[^\s/$.?#][^\s]*$', re.IGNORECASE)
    return bool(pattern.match(url_string))

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
    if result['hostname'] is None:
        return 0 , 0
    hyphen_count = result['hostname'].count('-')
    if('-' in result['hostname']):
        if(hyphen_count>=2):
            return 2,hyphen_count
        elif (hyphen_count==1):
            return 1,hyphen_count
        else:
            return 0,0
    else:
        return 0,0
    

def check_suspicious_tld(url_string):
    msg= ""
    result = get_url_components(url_string)
    if result['hostname'] is None:
        return 0,""
    _,ip_address_presence = check_ip_address(url_string)
    if str(ip_address_presence) in result['hostname']:
        msg="Ip address used instead of domain"
        return 1,msg
    x = result['hostname'].split('.')
    tld = '.'+ x[-1]
    file_path = os.path.join(get_base_path(),'data','tlds_scoring.json')
    with open(file_path, 'r') as f:
        unknown_tlds = json.load(f)
    msg="Suspicious top level domain found: "+ str(tld)
    if tld in unknown_tlds["high_risk"]:
        return 2,msg
    elif tld in unknown_tlds["medium_risk"]:
        return 1,msg
    elif tld in unknown_tlds["common_neutral"]:
        return 0,""
    return 0,"Top Level Domain may be suspicious"

def compiled_pattern_keyword(keywords):
    return{
        kw:re.compile(
            r'(^|[./-])'+ re.escape(kw).replace(r'\.', '[.-]')+r'([./-]|$)'
            )
        for kw in keywords
    }

keywords_path= os.path.join(get_base_path(),'data','suspicious_keywords.json')
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
file_path_shorteners = os.path.join(get_base_path(),'data','url_shorteners.txt')
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
    if len(parts) >= 3 and parts[-2] in KNOWN_SLD:
        subdomains = parts[:-3]
    else:
        subdomains = parts[:-2]
    if len(subdomains)>=3:
        return 2,subdomains
    elif len(subdomains)==2:
        return 0,subdomains
    return 0,""
def check_scheme(url_string):
    result = get_url_components(url_string)
    if result['scheme'] is None or result['scheme'] == "":
        return 2,result['scheme']
    if result['scheme'] == 'http':
        return 1,result['scheme']
    if result['scheme'] == 'https':
        return 0,""
    return 2,result['scheme']



file_path_domains = os.path.join(get_base_path(), 'data', 'legitimate_clean_doms.csv')
with open(file_path_domains, 'r') as f:
        legitimate_domains = [line.split(',')[1].strip() for line in f.read().splitlines() if ',' in line]
      
def normalize_domain(s):
    table = str.maketrans('013457', 'oleast')
    s = s.translate(table)
    result = []
    for c in s:
        if c.isascii() and c.isalpha():
            result.append(c)  
        elif c in confusables:
            result.append(confusables[c][0]),
        else:
            result.append(c)
    return ''.join(result)


NOISE_WORDS = {
    'http', 'https', 'www', 'secure', 'login', 
    'verify', 'account', 'update', 'portal', 
    'totally', 'total', 'local', 'my', 'xn'
    }
KNOWN_SLD = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'ne', 'or'}
def check_domain_similarity(url_string):
    result = get_url_components(url_string)
    if result['hostname'] is None:
        return 0,"",0
    parts = result ['hostname'].split('.')
    if len(parts) >= 3 and parts[-2] in KNOWN_SLD:
        domain = '.'.join(parts[-3:])
        subdomain = '.'.join(parts[:-3])
    else:
        domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
    if domain in url_shorteners:
        return 0,"",0

    normalized_domain = normalize_domain(domain)
    if "xn--" in result['hostname']:
        decoded_result= homograph.decode_domain(result['hostname'])
        if decoded_result is None:
            return 0, "", 0
        domain_match = process.extractOne(decoded_result, legitimate_domains, scorer=fuzz.ratio)
    else:
        domain_match = None
        highlight = None
        if '-' in domain:
            label = domain.split('.')[0]

            words = [
                w for w in label.split('-')
                if w not in NOISE_WORDS
                ]

            best_match=None
            best_ratio = 0

            for word in words:
                normalized_query = normalize_domain(word) + (
                ".com" 
                )

                match = process.extractOne(
                    normalized_query,
                    legitimate_domains,
                    scorer=fuzz.ratio
                )

                if match:
                    matched_domain,ratio,_=match
                    if ratio>best_ratio:
                        domain_match = match
                        best_ratio = ratio

        if domain_match is None:
            domain_match = process.extractOne(
                normalized_domain,
                legitimate_domains,
                scorer=fuzz.ratio
        )
            
    
    if domain_match is not None:
        matched_domain, ratio, _ = domain_match
        best_match = matched_domain
        best_ratio = ratio
        winning_query=domain
    normalized_subdomain=""
    if subdomain and subdomain not in NOISE_WORDS and len(subdomain) >= 4:
        normalized_subdomain = normalize_domain(subdomain)
        if '.' in normalized_subdomain:
            normalized_subdomain_base = normalized_subdomain.split('.')[0]
            possible_tld =normalized_subdomain.split('.')[1]
            normalized_subdomain =  normalized_subdomain_base+'.'+possible_tld
        subdomain_match = process.extractOne(normalized_subdomain, legitimate_domains, scorer=fuzz.ratio)

        if subdomain_match is not None:
            best_matched_domain, ratio_sub, _ = subdomain_match 
            if ratio_sub >=96:
                best_ratio = ratio_sub
                best_match = best_matched_domain 
                winning_query = normalized_subdomain
                
    if best_match is None:
        return 0, "",0
    if best_match == domain and best_ratio == 100:
        final_ratio = fuzz.ratio(domain, best_match)
    elif winning_query == normalized_subdomain:
        final_ratio = fuzz.ratio(result['hostname'], best_match)
    else:
   
        final_ratio = fuzz.ratio(result['hostname'], best_match)
        highlight = winning_query
        if highlight is None:
            pass
    highest_ratio = final_ratio/100
    
    if (highest_ratio == 1.0 and best_match == domain) and(result['scheme']=="https"):
        return -1, best_match,highest_ratio,highlight
    elif highest_ratio == 1.0:
        return 2, best_match,highest_ratio,highlight
    elif highest_ratio >=0.8 and highest_ratio < 1.0:
        return 2,best_match,highest_ratio,highlight
    elif highest_ratio >= 0.2 and highest_ratio < 0.8:
        return 1,best_match,highest_ratio,highlight
    return 0,"",highest_ratio,highlight
    
   

     
 
def analyse_url(url_string):
    hostname = get_url_components(url_string)['hostname']
    scheme = get_url_components(url_string)['scheme']
    if hostname is None:
        return "Invalid url please try again"
    if not is_valid_url(url_string):
        return {"error": "Invalid URL format"}
    else:
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
        keyword_set = set(word_list)
        if(keyword_score>0):
            if(counter>1):
                indicators.append("Keywords detected: "+ ",".join(keyword_set))
            else:
                indicators.append("Keyword detected: "+ ",".join(keyword_set))
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
            
        tld_score, tld_msg = check_suspicious_tld(url_string)
        score+=tld_score
        if(tld_score>0):
            indicators.append(tld_msg)
        similarity_scorer,close_match,highest_ratio,highlight=check_domain_similarity(url_string)
        score+=similarity_scorer
        
        homograph_score, homograph_message = homographchecker(hostname or '')
        score += homograph_score
        if homograph_score > 0:
            indicators.append("Homograph attack detected: " + ", ".join(homograph_message))
        
        if (score>=5):
            verdict="Dangerous"
        elif (score>=2):
            verdict= "Suspicious"
        elif (score>0):
            verdict= "Unknown website, Be cautious"
        else:
            verdict ="Legitimate" 
        
        
        
        output ={
        "score": score,
        "verdict": verdict,
        }
        
        if indicators:
            output["indicators"]=indicators
        output["highlight"]=highlight
        indicators.append(
        f"Domain resembles {close_match} ({int(highest_ratio*100)}% similar)"
        )
        
        suggestion_text=suggestion.suggest_domain(close_match)
        if "xn--"in hostname and (highest_ratio*100)<=0:
            output['Warning']= "DO NOT CLICK THIS LINK"
        elif close_match is not None and (highest_ratio*100)<30:
            output["Warning"] ="DOMAIN COULD NOT BE FOUND, do not proceed unless certain" 
        elif (suggestion_text and (highest_ratio*100)!=100):
            if (highest_ratio*100)>30:
                output["suggestion"] = suggestion_text +" ("+ str(int(highest_ratio*100))+"% "+"similar)"
        elif (suggestion_text and (highest_ratio*100)==100) and(scheme!="https" ):
                output["suggestion"] = suggestion_text +" ("+ str(int(highest_ratio*100))+"% "+"similar)"
        return output
