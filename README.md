# Scripts to scan for Microsoft Exchange Vulnerabilities

In 2021 several dangerous and widely exploited vulnerabilities for
Microsoft Exchange servers have been published. This repository
provides scripts to scan for

- [CVE-2021-26855](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-26855):
  The SSRF vulnerability which is the entry point for the
  [ProxyLogon](https://proxylogon.com/) exploit chain.
- [CVE-2021-34473](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-34473):
  The pre-auth path confusion which is the entry point for the
  [ProxyShell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
  exploit chain.
- [CVE-2021-33766](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-33766):
  The [ProxyToken](https://www.thezdi.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server)
  vulnerability which enables an unauthenticated attacker to perform
  configuration actions on mailboxes belonging to arbitrary users.

## CVE-2021-26855

For this vulnerability we use the same logic as [Microsoft's official
`nmap` script](https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/http-vuln-cve2021-26855.nse),
but in a Python3 implementation.

## CVE-2021-34473

This script was inspired by [Kevin Beaumont's `nmap` script](https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange-proxyshell.nse),
but again, we re-implemented it in Python3. This is basically a `GET`
request to a certain URL which classifies servers as vulnerable if
they respond with an HTTP status code `302 Found` and as patched
in case `400 Bad Request` is returned. However, we found several
Exchange servers which responded with other codes (mainly `401
Unauthorized`), so we added code to determine the version of 
the Exchange server in two ways:
1. Trying to parse it from the `X-OWA-Version` header in
  requests to `/autodiscover/autodiscover.xml` as described
  [here](https://www.msxfaq.de/exchange/update/exchange_build_nummer_ermitteln.htm#analyse_per_autod)
2. As the `X-OWA-Version` header is only present since the July 2021
  updates, so as a backup strategy for older servers, the script
  requests `/owa/` and tries to parse the version from the returned
  HTML. This was inpired by the `get_exchange_version` function in
  https://github.com/cert-lv/CVE-2020-0688/blob/master/lib.py

## CVE-2021-33677

Checking for CVE-2021-33677 a.k.a. [ProxyToken](https://www.thezdi.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server)
is currently very rudimentary: It actually just tries to determine
the version of the Microsoft Exchange server. As ProxyToken was fixed
in the July 2021 Security Updates, any Exchange servers running Exchange
2013, 2016, or 2019 with a patch level prior to that are considered
vulnerable.

## Usage example

The main script to run is `scan.py`:
```
$ python3 scan.py --help
usage: scan.py [-h] [--method METHOD] [--timeout TIMEOUT] [--scheme {https://,http://}] [--path PATH] [--threads THREADS] [--patched PATCHED]
               [--unknown UNKNOWN] [--debug]
               {cve-2021-26855,cve-2021-34473,cve-2021-33766} hostlist results

positional arguments:
  {cve-2021-26855,cve-2021-34473,cve-2021-33766}
                        The CVE number to scan for.
  hostlist              List of IPs/hostnames to scan. One IP/hostname per line
  results               CSV file to write vulnerable hosts to. Format: "ip","timestamp","exchange_version_number",exchange_version_name"

optional arguments:
  -h, --help            show this help message and exit
  --method METHOD       The HTTP method to use. Default: "GET"
  --timeout TIMEOUT     The timeout to use for requests in seconds. Default: 2
  --scheme {https://,http://}
                        Scheme of the request, i.e. "http://" or "https://".
  --path PATH           The path on the webserver.
  --threads THREADS     Max number of parallel requests. Default: 300
  --patched PATCHED     File to write patched hosts to.
  --unknown UNKNOWN     File to write hosts to whose status is not known (e.g. not an Exchange, OWA not active).
  --debug               Print debug information.
```
An example run to scan all hosts in `hosts.txt` for CVE-2021-34473
with default method, timeout, and number of threads:
```
$ python3 scan.py --path '/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com' \
                  --scheme 'https://' \
                  --patched $(date -Id)-patched.txt \
                  --unknown $(date -Id)-unknown.txt \
                  CVE-2021-34473 exchange-ips-at.txt $(date -Id)-vulnerable.txt
```
Example results for patched servers:
```
"mx0.example.com","2021-09-01T00:00:00+00:00","15.2.858.15","Exchange Server 2019 CU9 Jul21SU"
"198.51.100.58","2021-09-01T00:00:00+00:00","15.1.2308.14","Exchange Server 2016 CU21 Jul21SU"
"198.51.100.142","2021-09-01T00:00:00+00:00","15.1.2308.14","Exchange Server 2016 CU21 Jul21SU"
"198.51.100.35","2021-09-01T00:00:00+00:00","15.1.2308.14","Exchange Server 2016 CU21 Jul21SU"
"198.51.100.144","2021-09-01T00:00:00+00:00","15.1.2308.14","Exchange Server 2016 CU21 Jul21SU"
"198.51.100.61","2021-09-01T00:00:00+00:00","15.0.1473","Exchange Server 2013 CU22"
"exchange.example.com","2021-09-01T00:00:00+00:00","15.2.922","Exchange Server 2019 CU10"
"198.51.100.92","2021-09-01T00:00:00+00:00","15.0.1497.23","Exchange Server 2013 CU23 Jul21SU"
"198.51.100.183","2021-09-01T00:00:00+00:00","15.1.2308.14","Exchange Server 2016 CU21 Jul21SU"
"198.51.100.136","2021-09-01T00:00:00+00:00","15.0.1497.23","Exchange Server 2013 CU23 Jul21SU"
```

## Funding

This project is partially funded by the CEF framework

![Co-financed by the Connecting Europe Facility of the European Union](https://ec.europa.eu/inea/sites/default/files/ceflogos/en_horizontal_cef_logo_2.png)
