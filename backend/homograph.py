import idna
def detect_punycode(url_string):
    decoded_message = idna.decode(url_string)