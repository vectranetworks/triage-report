'''Perform a mail merge on template.docx to create the Triage Report'''
import logging
from datetime import date, datetime
from csv import reader
from os import path

from mailmerge import MailMerge

from csv_file import ALL_CSV_FILES

date_string = datetime.today().strftime(('%y%m%d'))

def write_report(title='VTR-' + date_string):
    '''write csv data to Word report'''
    title = 'VTR-' + date_string

    logging.debug('Open Report Template, will name file %s.docx', title)

    report = MailMerge('template.docx')

    report.merge(
        date        = date.today().strftime('%B %d, %Y'),   # November 01, 2021
        short_date  = date.today().strftime('%y%m%d')       # 211101
    )
    logging.info('Populating Word Tables')

    for csv_file in ALL_CSV_FILES:
        if path.exists(f'csv/{csv_file.name}.csv'):
            data = read_csv_data(csv_file.name, csv_file.columns)
            logging.debug('merging data from csv file %s', csv_file.name)
            report.merge_rows(csv_file.columns[0], data)
        else:
            logging.debug('csv file %s not found', csv_file.name)

    logging.info('Finished populating tables, writing output to %s.docx', title)

    # write output to a new Word file
    try:
        report.write(f'{title}.docx')
    except FileNotFoundError as my_file_error:
        logging.error('Error: %s', my_file_error)


def read_csv_data(filename, columns):
    '''Read CSV data'''
    with open(f'csv/{filename}.csv', newline='',encoding='UTF-8') as csvfile:
        csvreader = reader(csvfile)
        data = [ { column: entry for column, entry in zip(columns, row) } for row in csvreader ]
    return data
