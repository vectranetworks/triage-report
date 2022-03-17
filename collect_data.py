'''Get data from the brain'''

import os
import logging
from json import JSONDecodeError
from csv import writer
from tqdm import tqdm

from constants import PAGE_SIZE
from csv_file import DETECTION_CSV_FILES, GROUP_CSV_FILES, RULE_CSV_FILES
from score_range import ScoreRange, LOW, MEDIUM, HIGH, CRITICAL

# TODO: Get DC Services: detection.summary.roles:DC Services
# TODO: get Printers detection.summary.roles:Printer
# TODO: get Triage Opportunities
# tag=VSK - Triage Opportunity - [0-9]{4}-[0-9]{2}-[0-9]{2} - [A-Z]{2}


def collect_data(vectra_client, threat_score=0, certainty_score=0, severity=None):
    '''
    Collect data from vectra brain
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    :param int threat_score: Minimum threat score to consider
    :param int certainty_score: Minimum certainty score to consider
    :param str severity: Severity Score, Low Medium, High, Critical
    '''

    # make folder for csv files
    if not os.path.exists('csv'):
        os.mkdir('csv')

    score_ranges = []

    if severity:
        for sev_score in (x.lower() for x in severity):
            if sev_score == 'low':
                score_ranges.append(LOW)
            elif sev_score == 'medium':
                score_ranges.append(MEDIUM)
            elif sev_score == 'high':
                score_ranges.append(HIGH)
            elif sev_score == 'critical':
                score_ranges.append(CRITICAL)
            else:
                logging.warning('Severity level %s not valid. Valid security levels are low, '
                                'medium, high, and critical', sev_score)
    else:
        score_ranges.append(
            ScoreRange(min_threat=threat_score, min_certainty=certainty_score)
        )

    logging.info('Collecting data for CSV files')
    logging.debug('Filtering through groups')
    collect_groups(vectra_client)

    logging.debug('Filtering through rules')
    collect_rules(vectra_client)

    logging.debug('Filtering through detections')
    collect_detections(vectra_client, score_ranges)


def write_data_to_csv_file(filename, data):
    '''
    Take json data and turn it into a CSV
    :param string filename: name of csv file to write to
    :param generator data: generator object containing results returned from the brain
    '''
    try:
        logging.debug('Writing data to csv/%s.csv', filename)
        with open(f'csv/{filename}.csv', 'w', newline='', encoding='UTF-8') as csvfile:
            csv_writer = writer(csvfile)
            for item in data:
                csv_writer.writerow(item)
        logging.debug('Wrote data to csv/%s.csv', filename)
    except TypeError as my_error:
        logging.error(
            'An error occured while writing data to: csv/%s.csv.  %s', filename, my_error)


def collect_groups(vectra_client):
    '''
    Enumerate groups and write to csv file
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    '''
    print('downloading Groups')
    groups = get_groups(vectra_client, page_size=PAGE_SIZE)
    for group_type in GROUP_CSV_FILES:
        results = {}
        # for group in get_groups(vectra_client, fields=manage_fields(group_type.fields),
        #  page_size=PAGE_SIZE):
        for group in groups:
            try:
                data = group_type.extract(group)
                if data:
                    results.update(data)
            except TypeError as my_error:
                logging.error('An error occured while gathering data for group with id: '
                              '%d.  Unknown exception %s.  Proceeding to next group', group['id'], my_error)

        write_data_to_csv_file(
            group_type.name, group_type.filter(results.items()))


def collect_rules(vectra_client):
    '''
    Get the Triage Rules, and write them to a CSV
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    '''
    print('downloading Rules')
    rules = get_rules(vectra_client, page_size=PAGE_SIZE)
    for rule_type in RULE_CSV_FILES:
        results = {}
        # for rule in get_rules(vectra_client, fields=manage_fields(rule_type.fields),
        #  page_size=PAGE_SIZE):
        for rule in rules:
            try:
                data = rule_type.extract(rule)
                if data:
                    results.update(data)
            except TypeError as my_error:
                logging.error('An error occured while gathering data for rule with id: '
                              '%d.  %s.  Proceeding to next rule', rule['id'], my_error)

        write_data_to_csv_file(
            rule_type.name, rule_type.filter(results.items()))


def collect_detections(vectra_client, score_ranges):
    '''
    Gather the detections within the specificed Threat and Certainty score range
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    :param score_ranges
    '''
    print('downloading Detections (will take several minutes due to large data set)')
    detections = get_detections(vectra_client)
    for csv_file in DETECTION_CSV_FILES:
        results = {}
        for detection in detections:
            if 'src_host' in detection and detection['src_host'] and meets_host_requirements(
                score_ranges,
                detection['src_host']['threat'],
                detection['src_host']['certainty'],
            ):
                try:
                    for data in csv_file.extract(detection):
                        increment_key(results, data)
                except TypeError as my_error:
                    logging.error('An error occured while gathering data for detection with '
                                  'id: %d - %s. %s.', detection['id'], detection['detection_type'], my_error)
                except IndexError as my_error:
                    logging.error('An IndexError occured while gathering data for detection with id: '
                                  '%d. %s', detection['id'], my_error)
                    logging.debug('Detection Details | Category | %s | Detection | %s',
                                    detection['category'],detection['detection'])
                except AttributeError as my_attribute_error:
                    logging.debug('Attribute Error: %s in %s',
                                  my_attribute_error, data)

        write_data_to_csv_file(csv_file.name, csv_file.filter(results.items()))


def get_advanced_search(vectra_client, **kwargs):
    '''
    Function to grab data via the Vectra API Tools
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    Throwing ValueError, expected types for stype are detections, hosts, or accounts
    '''
    for page in vectra_client.advanced_search(**kwargs):
        for detection in page.json()['results']:
            yield detection


def get_groups(vectra_client, **kwargs):
    '''
    Obtain all of the groups via a generator object
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    '''
    for page in vectra_client.get_all_groups(**kwargs):
        for group in page.json()['results']:
            yield group


def get_rules(vectra_client, **kwargs):
    '''
    Obtain all of the triage rules via a generator object
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    '''
    for page in vectra_client.get_all_rules(**kwargs):
        for rule in page.json()['results']:
            yield rule


def get_detections(vectra_client):
    '''
    Obtain all of the detections rules via a generator object
    :param VectraClientV2_1 vectra_client: Vectra Tools API connection object
    '''
    try:
        finalResults = []
        # Loop 7 times to make sure that API limits aren't hit.
        for i in tqdm(range(7)):
            response = vectra_client.advanced_search(stype='detections', page_size=5000,
                                                     query='detection.last_timestamp:[now-'+str((i+1)*5)+'d to now-'+str(i*5)+'d] and detection.state: active')

            results = next(response)
            try:
                while(results.json()['next']):
                    finalResults += results.json()['results']
                    results = next(response)
                # Add the final one
                finalResults += results.json()['results']
            except:
                print('Failed to get final page of results')
        return finalResults

    except JSONDecodeError as my_error:
        logging.error('An error occured while gathering data %s', my_error)


def increment_key(dictionary, key):
    '''
    For a given dictionary of key(s) walk through the dictionary
    '''
    try:
        if key:
            if key in dictionary:
                dictionary[key] += 1
            else:
                dictionary[key] = 1
    except IndexError as my_error:
        logging.error('Index Error: %s in %s at %s', my_error, dictionary, key)


def manage_fields(fields=None):
    '''
    Return the requested fields, all by default.  If fields are specified
    that don't include id or src_host, those are added
    '''
    if fields is not None:
        if 'src_host' not in fields:
            fields.append('src_host')
        if 'id' not in fields:
            fields.append('id')
        return ','.join(fields)
    return None  # if no fields are specified, None will retrieve all fields


def meets_host_requirements(score_ranges, threat, certainty):
    '''
    Returns True if the it meets requirements, false otherwise
    '''
    return (threat or certainty) and any(
        score_range.in_range(threat, certainty) for score_range in score_ranges
    )
