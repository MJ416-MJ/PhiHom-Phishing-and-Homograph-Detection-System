import os
import unicodedata
import idna
import sys
def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(__file__)

def get_scripts(domain):
    parts = domain.split(".")
    joined_words = "".join(parts[:-1])

    scripts = set()

    for char in joined_words:
        if not char.isalpha():
            continue

        try:
            name = unicodedata.name(char)
            scripts.add(name.split()[0])
        except ValueError:
            continue

    return scripts
def check_script(domain):
    parts = domain.split(".")
    domain_words = parts[:-1]
    joined_words="".join(domain_words)
    scripts = get_scripts(domain)
    swapped_script = []
    for char in joined_words:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        if not name.startswith("LATIN"):
            swapped_script.append("["+char+"]" + " is a "+str(name.split()[0])+" character in a mixed-script domain ")
        
    
    if len(scripts)>1:
        return 2,swapped_script
    return 0,""

file_path = os.path.join(get_base_path(),'data','confusables.txt')
with open(file_path,'r', encoding='utf-8-sig') as f:
    confusables = {}
    for line in f.read().splitlines():
        if line.startswith("#") or ";" not in line:
            continue
        parts = line.split(";")
        source = chr(int(parts[0].strip(), 16))
        target_hex = parts[1].strip().split()
        target = "".join((chr(int(code, 16)) for code in target_hex))
        target_name = ' + '.join(
            unicodedata.name(c, 'UNKNOWN') for c in target
        )
        confusables[source] = (target, target_name)

def decode_domain(domain):
    parts=domain.split(".")
    decoded_part = []
    for part in parts:
        if part.startswith("xn--"):
            try:
                decoded_part.append(idna.decode(part.encode()))
            except idna.IDNAError as e:
                return None
        else:
            decoded_part.append(part)

        
    return ".".join(decoded_part)
    

def check_idna(domain):
    decoded_domain =decode_domain(domain)
    if decoded_domain is None:
        return 2, "Invalid Punycode encoding"
    has_punycode = False
    if decoded_domain != domain:
        has_punycode = True 
    score,found = check_script(decoded_domain)
    if(score == 2 and has_punycode):
        msg = "Punycode detected, decoded to "+ decoded_domain + " contains mixed scripts " + str(found)
        return 2,msg
    return 0,""
        
def check_confusables(domain,highest_ratio=0):
    
    if highest_ratio <0.35:
        return 0,""
    parts = domain.split(".")
    joined_words="".join(parts[:-1])
    found =[]
    for char in joined_words:
        if not char.isalpha():
            continue
        if char in confusables:
            char_name = unicodedata.name(char,'UNKNOWN')
            if not char_name.startswith('LATIN'):
                target,target_name = confusables[char]
                found.append("["+char+"]" + " is a (" + char_name.split()[0] + ") character that looks like " + "["+target+"]" + " which is a (" + target_name.split()[0] + ") character")
    if found:
        return 2,found
    return 0,""
    
def homographchecker(domain,highest_ratio=0):
    script_score, script_message = check_script(domain)
    confusables_score, confusable_message = check_confusables(domain, highest_ratio)
    idna_score, idna_message = check_idna(domain)
    total_score = max(script_score, confusables_score, idna_score)
    message = []
    if confusables_score>0:
        message.extend(confusable_message)
    elif script_score>0:
        message.append(script_message)
    if idna_score>0:
        message.append(idna_message)
    if message:
        return total_score,message
    else:
        return total_score,""
