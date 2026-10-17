import urllib.request

def is_image(data):
    return data[:4] in (b"\x89PNG", b"\xff\xd8\xff\xe0")

def fetch_avatar(url):
    # VULNERABLE (line 7): SSRF, no validation of url
    return urllib.request.urlopen(url).read()
