import pickle
import os

CACHE_DIR = "/tmp/cache"

def cache_key(name):
    return os.path.join(CACHE_DIR, name + ".bin")

def load_cached(name):
    with open(cache_key(name), "rb") as f:
        # VULNERABLE (line 12): untrusted deserialization
        return pickle.loads(f.read())

def store_cached(name, obj):
    with open(cache_key(name), "wb") as f:
        f.write(pickle.dumps(obj))
