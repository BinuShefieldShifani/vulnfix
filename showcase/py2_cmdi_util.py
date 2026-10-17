import os
import logging

log = logging.getLogger(__name__)

def sanitize_name(name):
    return name.strip()

def backup(target):
    # VULNERABLE (line 11): command injection
    os.system("tar czf /backups/" + target + ".tgz /data/" + target)
    log.info("backed up %s", target)
