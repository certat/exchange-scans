# SPDX-FileCopyrightText: 2021 Dimitri Robl
#
# SPDX-License-Identifier: MIT

import re
import requests
import sys

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_exchange_version(host, timeout: int, scheme='https', debug=False):
    '''get_exchange_version: Try to determine the version of a Microsoft
          Exchange installation. Two methods are tried: 
          1. Get the exact version via the 'X-OWA-Version' header
             from the '/autodiscover/autodiscover.xml' file possible
             since July 2021, see e.g. https://www.msxfaq.de/exchange/update/exchange_build_nummer_ermitteln.htm#analyse_per_autod
          2. Try to parse the version from the HTML return by OWA.
             This has been inspired by the get_exchange_version function in
             https://github.com/cert-lv/CVE-2020-0688/blob/master/lib.py
             with a more aggressive regex.
         Arguments:
          host (str)    : The host to get the version from. Can be
                          either an IP address or a hostname.
          timeout (int) : The timeout for the connection.
          scheme (str)  : The scheme to use, defaults to 'https://'
          debug (bool)  : If True, print debugging output do stderr.
        Return values:
          version (str) : If either method succeeds, the parsed version
                          is returned, otherwise "None" is returned.
    '''
    regex = re.compile(b'href="/owa/(auth/)?(?P<version>[14568][45]?\.[0-9\.]+)/.*"')
    headers = {
      'Accept-Encoding': 'gzip, deflate',
      'Accept': '*/*',
      'Connection': 'keep-alive',
      'User-Agent' : 'get_exchange_version',
    }
    session = requests.session()
    session.headers = headers
    session.verify = False
    try:
        auto_path = '/autodiscover/autodiscover.xml'
        auto_url = scheme + host + auto_path
        if debug:
            print(f'Requesting autodiscover URL "{auto_url}"',
                  file=sys.stderr)
        resp = session.get(auto_url)
        try:
            return resp.headers['X-OWA-Version']
        except KeyError:
            if debug:
                print(f'{auto_url}: No "X-OWA-Version" header.',
                      file=sys.stderr)
    except Exception as e:
        if debug:
            print(f'Failed to parse version via autodiscover: {e}',
                  file=sys.stderr)
    try:
        owa_path = '/owa/'
        owa_url = scheme + host + owa_path
        if debug:
            print(f'Requesting OWA "{owa_url}"', file=sys.stderr)
        resp = requests.get(owa_url, timeout=timeout, verify=False)
        for line in resp.iter_lines():
            match = regex.search(line)
            if match:
                return match.group('version').decode()
    except Exception as e:
        if debug:
            print(f'Failed to parse version from OWA: {e}',
                  file=sys.stderr)
    return None
# end get_exchange_version

def is_vulnerable_to_cve_2021_26855(host, timeout=5, method='GET',
                  scheme='https://', path='/owa/auth/x.js',
                  debug=False):
    '''is_vulnerable_to_csv_2021_26855: Function to check Exchange
          Servers for being vulnerable to CVE-2021-26855 inpired by
          https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/http-vuln-cve2021-26855.nse
    '''
    header = {
      'Accept-Encoding': 'gzip, deflate',
      'Accept': '*/*',
      'Connection': 'keep-alive',
      'User-Agent' : 'Check for CVE-2021-26855',
      'Cookie' : 'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;',
    }
    url = scheme + host + path
    try: 
        if debug:
            print(f'Requesting "{url}"', file=sys.stderr)
        response = requests.request(method, url, headers=header,
                                    verify=False,timeout=timeout,
                                    allow_redirects=False)
    except Exception as e:
        if debug:
            print(f'Request to {url} failed with {e}', file=sys.stderr)
        return (None, None)
    if debug:
        print('Trying to determine version...', file=sys.stderr)
    version = get_exchange_version(host, timeout, scheme, debug=debug)
    if debug:
        print(f'{host}: {response.status_code} -- {version}',
              file=sys.stderr)
    try:
        target = response.headers['x-calculatedbetarget']
    except KeyError:
        return (False, version)
    if 'localhost' in target:
        return (True, version)
    else:
        return (False, version)
# end is_vulnerable_to_cve_2021_26855

def is_vulnerable_to_cve_2021_34473(host, timeout=5, method='GET', 
                  scheme='https://', path='/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com',
                  debug=False):
    '''is_vulnerable_to_csv_2021_34473: Function to check Exchange
          Servers for being vulnerable to CVE-2021-34473 inspired by
          https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange-proxyshell.nse
          Known problems: 
            - Doesn't do reverse lookups on IP addresses, i.e. if
              access is only possible via a hostname it may result in
              false negatives when an IP address is scanned. The nmap
              script doesn't suffer from this flaw.
            - Only tries one scheme and not automatically 'https://'
              and 'http://'. The namp script doesn't suffer
              from this limitation.
        Arguments:
          host (str) : The host to check. Can be an IP address or
                        a hostname.
          timeout (int) : The timeout for the request in seconds.
                          Default: 5
          method (str)  : The HTTP method to use. Default: "GET"
          scheme (str)  : The scheme to use. Default: "https://"
          path (str)    : The path on the server to access. The
                          default is the path from the original nmap
                          script.
          debug (bool)  : If True, print debugging output do stderr.
        Return values:
          (status, version) (tuple): "status" is a bool if it could
                        be determined whether the host is vulnerable
                        or not. Otherwise it is "None". "version"
                        is the value returned from get_exchange_version
                        or "None" if the request to the host failed.
    '''
    header = {
      'User-Agent' : 'Check for CVE-2021-34473',
    }
    url = scheme + host + path
    try: 
        if debug:
            print(f'Requesting "{url}"', file=sys.stderr)
        response = requests.request(method, url, headers=header,
                                    verify=False,timeout=timeout,
                                    allow_redirects=False)
    except Exception as e:
        if debug:
            print(f'Request to {url} failed with {e}', file=sys.stderr)
        return (None, None)
    if debug:
        print('Trying to determine version...', file=sys.stderr)
    version = get_exchange_version(host, timeout, scheme, debug=debug)
    if version:
        parts = version.split('.')
        major = int(parts[0])
        minor = int(parts[1])
        cu = int(parts[2])
        try: 
            su = int(parts[3])
        except IndexError:
            su = 0
        if major == 15 and minor == 2: # Exchange 2019
            if cu >= 922: # CU10 and above are not affected
                return (False, version)
            elif cu == 858 and su >= 10: # CU9, SU from April 2021 or later
                return (False, version)
            elif cu == 792 and su >= 13: # CU8, SU from April 2021 or later
                return (False, version) 
        elif major == 15 and minor == 1: # Exchange 2016
            if cu >= 2308: # CU21 and above are not affected
                return (False, version)
            elif cu == 2242 and su >= 8: # CU20, SU from April 2021 or later
                return (False, version)
            elif cu == 2176 and su >= 12: # CU19, SU from April 2021 or later
                return (False, version)
        elif major == 15 and minor == 0: # Exchange 2013
            if cu == 1497 and su >= 15: # CU23, SU from April 2021 or later
                return (False, version)
    if debug:
        print(f'{host}: {response.status_code} -- {version}',
              file=sys.stderr)
    if response.status_code == 302:
        return (True, version)
    elif response.status_code == 400:
        return (False, version)
    else:
        return (None, version)
# end is_vulnerable_to_cve_2021_34473

def is_vulnerable_to_cve_2021_33766(host, timeout=5, method='POST',
                  scheme='https://', path='/ecp/postmaster@{}/RulesEditor/InboxRules.svc/NewObject',
                  debug=False):
    '''is_vulnerable_to_cve_2021_33766: Checks if an Exchange
          installation is vulnerable to CVE-2021-33766. For a detailed
          description of the vulnerability see
          https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server
          Currently, this only tries to check the version number
          to check for the vulnerability.
        Arguments:
          host (str)    : The host to check. Can be an IP address or
                        a hostname.
          timeout (int) : The timeout for the request in seconds.
                          Default: 5
          method (str)  : The HTTP method to use. Default: "POST"
          scheme (str)  : The scheme to use. Default: "https://"
          path (str)    : The path on the server to access. This
                          argument is currently not used.
          debug (bool)  : If True, print debugging output do stderr.
        Return values:
          (status, version) (tuple): "status" is a bool if it could
                        be determined whether the host is vulnerable
                        or not. Otherwise it is "None". "version"
                        is the value returned from get_exchange_version
                        or "None" if the request to the host failed.
    '''
    if debug:
        this = is_vulnerable_to_cve_2021_33766
    header = {
      'User-Agent'  : 'Check for CVE-2021-33766',
      'Cookie'      : 'SecurityToken=x',
    }
    if debug:
        print('Trying to determine version...', file=sys.stderr)
    version = get_exchange_version(host, timeout, scheme, debug=debug)
    if debug:
        print(f'Version found: "{version}"')
    if version:
        parts = version.split('.')
        major = int(parts[0])
        minor = int(parts[1])
        cu = int(parts[2])
        try: 
            su = int(parts[3])
        except IndexError:
            su = None
        if major == 15 and minor == 2: # Exchange 2019
            if cu <= 792: # CU8 and below are vulnerable
                return (True, version) 
            elif cu > 922: #CU11 and later -- not released at time of writing (2021-09-03)
                return (False, version)
            elif su:
                if cu == 922: # CU10
                    if su >= 13: # SU from July 2021 or later
                        return (False, version)
                    else:
                        return (True, version)
                elif cu == 858 and su >= 15: # CU9
                    if su >= 15: # SU from July 2021 or later
                        return (False, version)
                    else:
                        return (True, version)
        elif major == 15 and minor == 1: # Exchange 2016
            if cu > 2308: # CU22 and later -- not released at time of writing (2021-09-03)
                return (False, version)
            elif cu < 2242: # CU 19 and below are vulnerable
                return (True, version)
            elif su:
                if cu == 2242: # CU20
                    if su >= 12: # SU from July 2021 or later
                        return (False, version)
                    else:
                        return (True, version)
        elif major == 15 and minor == 0: # Exchange 2013
            if cu < 1497: # CU22 and below are vulnerable
                return (True, version)
            elif su:
                if cu == 1497: # CU23
                    if su >= 23: # SU from July 2021 or later
                        return (False, version)
                    else:
                        return (True, version)
        else:
            return (None, version)
    else:
        return (None, None)
# end is_vulnerable_to_cve_2021_33766
