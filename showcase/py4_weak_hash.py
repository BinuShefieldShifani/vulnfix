import hashlib

def normalize(pw):
    return pw.strip()

def hash_password(pw):
    pw = normalize(pw)
    # VULNERABLE (line 8): MD5 for passwords
    return hashlib.md5(pw.encode()).hexdigest()
