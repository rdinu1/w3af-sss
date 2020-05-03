#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS
from urllib.parse import urlparse   ###import urlparse

__product__ = "Tencent Cloud Web Application Firewall (Tencent Cloud Computing)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)
        domain = urlparse(page).hostname 
        retval = code == 405 and (domain and domain.startswith("waf.tencent-cloud.com")) 
        
        if retval:
            break

    return retval
