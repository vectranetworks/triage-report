#!/usr/bin/env python3

'''
Triage Report
Take a Brain URL, and API token, and output CSVs for a triage report
or a full Triage Report
'''

__version__ = '1.1.0'
__author__  = 'Eric Martin'
__contact__ = 'emartin@vectra.ai'

try:
    import logging
    import os
    import sys
    from argparse import ArgumentParser, RawTextHelpFormatter
    from datetime import datetime
    from getpass import getpass

    import requests
    from urllib3 import disable_warnings, exceptions
    from vat.vectra import HTTPException, VectraClientV2_2

    from ansi_colors import GREEN, RED, RESET, YELLOW
    from collect_data import collect_data
    from write_data import write_report

except ModuleNotFoundError as module_error:
    print(module_error,' Try running pip3 install -r requirements.txt')

# Expecting SSL error from brain due to signing cert, so disable warnings
disable_warnings(exceptions.InsecureRequestWarning)

# TODO: Santize Args
def main():
    '''Setup Logging and collect data'''
    args = config_args(sys.argv[1:])
    if not os.path.exists('log'):
        os.mkdir('log')
    logging.basicConfig(
        # https://docs.python.org/3/library/logging.html
        datefmt='%F %H:%M:%S%z', # microseconds are unavailable in datefmt
        filename='log/triage_report-' + datetime.today().strftime('%F') + '.log',
        format='%(asctime)s %(levelname)s %(filename)s:%(funcName)s:%(lineno)d %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    vectra_client = setup_vectra_client(url=args.cognito_url,token=args.cognito_token)

    assert not (args.tc and args.severity)

    if args.report_only:
        write_report()
    else: #if args.tc:
        if args.tc:
            collect_data(vectra_client, threat_score=args.tc[0], certainty_score=args.tc[1])
        elif args.severity:
            collect_data(vectra_client, severity=args.severity)
        else:
            collect_data(vectra_client)

    if not args.csv_only:
        write_report()


def config_args(args):
    '''Parse CLI arguments'''
    parser = ArgumentParser(
        description='Generate Triage Report, version ' + __version__,
        formatter_class=RawTextHelpFormatter,
        epilog='Example: triage_report.py --cognito_url https://brain.vectra.ai' +
            ' --cognito_token AAABBBCCCDDD' +
            ' Vectra --severity high low',
    )
    parser.add_argument('--cognito_token', type=str)
    parser.add_argument('--cognito_url', '--cognito-url', type=str)
    parser.add_argument('--company_name', type=str, default=False)
    parser.add_argument('--csv_only', action='store_true')
    parser.add_argument('--debug', action='store_true')

    parser.add_argument('--report_only', action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--tc', nargs=2, type=int)
    group.add_argument('--severity', nargs='+')

    return parser.parse_args(args)


def setup_vectra_client(url,token):
    '''
    Use Vectra API Tools to setup API access
    :param ArgumentParser args: Parsed arguments passed to the program
    '''
    if url is None:
        url = input('Enter Cognito URL: ')
    if token is None:
        token = getpass('Enter Cognito API Token (characters will not display): ')

    logging.info('Connecting to %s',url)
    print('Attempting to connect to brain at ' + YELLOW + url + RESET)

    brain = VectraClientV2_2(url=url, token=token)

    try:
        brain.get_health_check().content
    except requests.exceptions.MissingSchema as connection_error:
        logging.error('Incorrect Schema used when connecting. %s',connection_error)
        sys.exit(RED + 'Incorrect Schema used when connecting. ' +
            YELLOW + 'Perhaps you meant https://' + url + RESET)

    except requests.exceptions.InvalidSchema as connection_error:
        logging.error('Invalid Schema used when connecting. %s',connection_error)
        sys.exit(RED + 'Invalid URL. Please enter the url in the form of https://brain.vectra.ai'
            + RESET)

    except requests.exceptions.ConnectionError as connection_error:
        logging.error('Connection error when connecting to %s.  %s',
                        url,connection_error)
        sys.exit(RED + 'Error: Unable to connect to ' + url +
                '. Max retries exceeded.  Check the connection and try again' + RESET)

    except HTTPException as connection_error:
        logging.error('HTTP Exception when connecting to %s. %s',
                        url,connection_error)
        sys.exit(RED + 'An HTTP Exception occurred. This could be due to invalid credentials' +
            RESET)

    except Exception as unknown_error:                              #pylint: disable=broad-except
        logging.error('Unknown Error: %s',unknown_error)
        sys.exit(RED + unknown_error + RESET)

    print('Successfully connected to ' + GREEN + url + RESET)
    logging.info('Successfully connected to %s',url)
    return brain


if __name__ == '__main__':
    main()
