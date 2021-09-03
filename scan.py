# SPDX-FileCopyrightText: 2021 Dimitri Robl
#
# SPDX-License-Identifier: MIT

import argparse
import csv
import concurrent.futures
import datetime
import exchange_lib
import get_list_of_exchange_versions as gev
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('cve', type=str.lower, choices = 
                        ['cve-2021-26855', 'cve-2021-34473',
                        'cve--2021-33766'], 
                        help='The CVE number to scan for.')
    parser.add_argument('hostlist', type=argparse.FileType('r'),
                        help='List of IPs/hostnames to scan. One'
                        ' IP/hostname per line')
    parser.add_argument('results', type=argparse.FileType('w'),
                        help='CSV file to write vulnerable hosts to.'
                        ' Format: "ip","timestamp","exchange_version_number",'
                        'exchange_version_name"')
    parser.add_argument('--method', default='GET', 
                        help='The HTTP method to use. Default: "GET"')
    parser.add_argument('--timeout', type=int, default=2,
                        help='The timeout to use for requests in seconds.'
                        ' Default: 2')
    parser.add_argument('--scheme', choices=['https://', 'http://'], 
                        help='Scheme of the request, i.e. "http://" or'
                        ' "https://".')
    parser.add_argument('--path', help='The path on the webserver.')
    parser.add_argument('--threads', type=int, default=300,
                        help='Max number of parallel requests. Default:'
                        ' 300')
    parser.add_argument('--patched', type=argparse.FileType('w'),
                        help='File to write patched hosts to.')
    parser.add_argument('--unknown', type=argparse.FileType('w'),
                        help='File to write hosts to whose status is not'
                        ' known (e.g. not an Exchange, OWA not active).')
    parser.add_argument('--debug', action='store_true', help='Print debug'
                        ' information.')

    args = parser.parse_args()

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    vulnerable = []
    patched = []
    unknown = []

    hosts = []
    for line in args.hostlist.readlines():
        host = line.strip()
        hosts.append(host)

    headers = {
      'User-Agent' : 'get_list_of_exchange_versions'
    }
    soup = gev.get_soup('https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates',
                        headers)
    tables = gev.get_tables(soup)
    exchange_mappings = gev.combine_dicts(tables, 'number_to_name', debug=args.debug)

    if args.cve == 'cve-2021-26855':
        is_vulnerable = exchange_lib.is_vulnerable_to_cve_2021_26855
    elif args.cve == 'cve-2021-34473':
        is_vulnerable = exchange_lib.is_vulnerable_to_cve_2021_34473
    elif args.cve == 'cve-2021-33766':
        is_vulnerable = exchange_lib.is_vulnerable_to_cve_2021_33766
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {executor.submit(is_vulnerable, host, args.timeout,
                                        args.method,scheme=args.scheme,
                                        path=args.path, debug=args.debug): host for host in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try: 
                version = future.result()[1]
                if version == None:
                    name = ''
                else:
                    found = False
                    for key in exchange_mappings.keys():
                        if key.startswith(version):
                            found = True
                            name = exchange_mappings[key]
                            if len(version.split('.')) == 3:
                                name_list = name.split(' ')
                                if name_list[-1].startswith('CU') or name_list[-1] in ['Preview', 'RTM']:
                                    pass
                                else:
                                    name = ' '.join(name_list[0:len(name_list)-1])
                            break
                    if not found:
                        name = ''
                if future.result()[0]:
                    vulnerable.append([host, timestamp, version, name])
                elif future.result()[0] == False:
                    patched.append([host, timestamp, version, name])
                else:
                    unknown.append([host, timestamp, version, name])
            except Exception as e:
                print('Exception occured:', e)

    writer = csv.writer(args.results, dialect='unix')
    writer.writerows(vulnerable)

    if args.patched:
        writer = csv.writer(args.patched, dialect='unix')
        writer.writerows(patched)
    if args.unknown:
        writer = csv.writer(args.unknown, dialect='unix')
        writer.writerows(unknown)

if __name__ == '__main__':
    main()
