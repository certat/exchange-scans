# SPDX-FileCopyrightText: 2021 Dimitri Robl
#
# SPDX-License-Identifier: MIT

import bs4
import pandas
import requests
import sys

def get_soup(url: str, headers: dict, timeout=2, debug=False):
    '''get_soup: Get the HTML content of a website and parse it into
        a bs4.BeautifulSoup object.
      Arguments:
        url (str)     : The URL to get.
        headers (dict): The headers to use for the request.
        timeout (int) : The timeout for the request in seconds.
                        Default: 2
        debug (bool)  : If True, print debug output.
      Return values:
        soup (bs4.BeautifulSoup): The resulting object.
    '''
    try:
        if debug:
            print(f'Requesting "{url}"...', file=sys.stderr)
        resp = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        if debug:
            print(f'[-] Request for "{url}" failed with {e}',
                  file=sys.stderr)
        return None
    try:
        soup = bs4.BeautifulSoup(resp.content, 'html.parser')
    except Exception as e:
        if debug:
            print(f'[-] Failed to parse HTML', file=sys.stderr)
        return None
    return soup
# end get_soup

def get_tables(soup: bs4.BeautifulSoup, debug=False):
    '''get_tables: Extract all tables from an HTML page parsed into
        a bs4.Beautiful soup.
      Arguments:
        soup (bs4.BeautifulSoup): The soup to extract the tables from.
        debug (bool): If True, print debug output.
      Return values:
        tables (bs4.element.ResultSet): All tables which have been
          found.
    '''
    try:
        tables = soup.findAll('table')
    except Exception as e:
        if debug:
            print('[-] Extracting tables from soup failed.',
                  file=sys.stderr)
        return None
    return tables
# end get_tables

def get_table_rows(table: bs4.element.ResultSet, debug=False):
    '''get_table_rows: Convert an HTML table parsed by
      bs4.BeautifulSoup into a list, ignoring empty rows and rows
      which consist only of empty strings.
      Arguments:
        table (bs4.element.ResultSet): The table to parse
        debug (bool) : If True, print debug output.
      Return values:
        rows (list): The resulting list.
    '''
    rows = []
    for tr in table.findAll('tr'):
        cells = []
        for td in tr.findAll('td'):
            cells.append(td.text.strip())
        if cells in [[], ['', '', ''], ['', '', '', '']]: 
            continue
        rows.append(cells)
    if debug:
        print(f'Resulting list: "{rows}"', file=sys.stderr)
    return rows
# end get_table_rows

def map_product_name_to_build_number(table_as_list: list, debug=False):
    '''map_product_name_to_build_number: Create a dictionary where
        keys are the names of Exchange servers and values are the
        build numbers. We use the short buildnumbers for mapping as
        these are the ones used in the HTML in OWA and the
        X-OWA-Version headers we've seen so far. Long buildnumbers
        pad all fields with zeroes, e.g. short "15.2.922.13" vs.
        long "15.02.0922.013".
      Arguments:
        table_as_list (list): An HTML table parsed into a list of
          lists, each sublist containing one row of the table.
        debug (bool) : If True, print debug output.
      Return values:
        mapping (dict) : The resulting dictionary.
    '''
    mapping = {}
    product_name_idx = 0
    relase_date_idx = 1
    build_number_short_idx = 2
    for entry in table_as_list:
        mapping[entry[product_name_idx]] = entry[build_number_short_idx]
    if debug:
        print(f'Mapping result: "{mapping}"', file=sys.stderr)
    return mapping
# end map_product_name_to_build_number
    
def map_build_number_to_product_name(table_as_list: list, debug=False):
    '''map_build_number_to_product_name: Create a dictionary where
        keys are the build numbers of Exchange servers and values are
        the names. We use the short buildnumbers for mapping as
        these are the ones used in the HTML in OWA and the
        X-OWA-Version headers we've seen so far. Long buildnumbers
        pad all fields with zeroes, e.g. short "15.2.922.13" vs.
        long "15.02.0922.013".
      Arguments:
        table_as_list (list): An HTML table parsed into a list of
          lists, each sublist containing one row of the table.
        debug (bool) : If True, print debug output.
      Return values:
        mapping (dict) : The resulting dictionary.
    '''
    mapping = {}
    product_name_idx = 0
    relase_date_idx = 1
    build_number_short_idx = 2
    for entry in table_as_list:
        mapping[entry[build_number_short_idx]] = entry[product_name_idx]
    if debug:
        print(f'Mapping result: "{mapping}"', file=sys.stderr)
    return mapping
# end map_product_name_to_build_number

def combine_dicts(dictlist: list, direction: str, debug=False):
    '''combine_dicts: Combine all the lists created from the HTML
        tables to a single dictionary.
      Arguments:
        dictlist (list) : The list containing all the lists.
        direction (str) : Whether the resulting dict should map
                          names to version strings or vice versa.
        debug (bool)    : If True, print debug output.
      Return values:
        mappings (dict) : The resulting combined dictionary.
    '''
    direction = direction.lower()
    if direction == 'name_to_number':
        map_function = map_product_name_to_build_number
    elif direction == 'number_to_name':
        map_function = map_build_number_to_product_name
    if debug:
        print(f'Mapping direction: {direction}', file=sys.stderr)
    mappings = {}
    for table in dictlist:
        rows = get_table_rows(table, debug=debug)
        mapping = map_function(rows)
        mappings.update(mapping)
    if debug:
        print(f'Resulting complete dictionary: "{mappings}"', 
              file=sys.stderr)
    return mappings
# end combine_dicts
    
            
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', '-u',
                        default='https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates',
                        help='URL to download list of Exchange Server'
                        ' versions from. Default:'
                        ' https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates')
    parser.add_argument('--mapping', '-m',
                        choices=['name_to_number', 'number_to_name'],
                        help='Create a dictionary of Exchange versions'
                        ' either mapping "Product name" : "Version'
                        ' String" or "Version String" : "Product'
                        ' Name".')
    parser.add_argument('--user-agent', 
                        help='User agent to use.')
    parser.add_argument('--timeout', '-t', type=int, default=2,
                        help='Timeout for requests. Default: 2')
    parser.add_argument('--debug', action='store_true',
                        help='Print debugging output to stderr.')
    args = parser.parse_args()
    debug = args.debug
    headers = {
      'User-Agent' : args.user_agent,
    }
    soup = get_soup(args.url, headers, timeout=args.timeout,
                    debug=debug)
    tables = get_tables(soup, debug=debug)
    mapping = combine_dicts(tables, args.mapping, debug=debug)
    print('{')
    for key, value in mapping.items():
        print(f'  "{key}" : "{value}",')
    print('}')



