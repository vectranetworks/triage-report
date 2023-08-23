'''Write the CSV file'''
try:
    import logging
    from datetime import datetime

    from constants import LIST_SIZE, SIX_MONTHS_AGO, THREE_MONTHS_AGO

except ModuleNotFoundError as module_error:
    print(module_error,' Try running pip3 install -r requirements.txt')

def not_triaged(detection):
    '''
    Take a detection and return True if triage_rule_id is None
    '''
    return detection['triage_rule_id'] is None


class EmptyGroup:
    '''
    Empty Group - Table 14
    Setup filename, file columns
    '''
    name = 'empty_group'
    columns = ['14_group_name', '14_id']
    # fields = ['members', 'id', 'name']

    @staticmethod
    def extract(group):
        try:
            if not group['members']:
                return {group['id']: group['name']}
        except KeyError as e:
            logging.error(e)
            return {group['id']: group['name']}

    @staticmethod
    def filter(data):
        return ((item[1], item[0]) for item in data)


GROUP_CSV_FILES = [EmptyGroup]


class ThreeMonths:
    '''
    Table 1 - Rules That Have Not Triggered in the Last 3 Months
    There are rules on your system that have not triggered in at least 3 months. There are no
    active detections affected by these rules. The behavior may no longer be expected on your
    network or the rule has been consolidated elsewhere.

    '''
    name = 'three_months'
    columns = ['1_detection_name', '1_id', '1_rule_name']
    # fields = ['last_timestamp', 'id', 'detection', 'triage_category']
    fields = None

    @staticmethod
    def extract(rule):
        datestr = rule['last_timestamp']
        if datestr is not None:
            triggered_date = datetime.strptime(datestr[:10], '%Y-%m-%d')
            if triggered_date <= THREE_MONTHS_AGO and triggered_date >= SIX_MONTHS_AGO:
                return {
                    rule['id']: (rule['detection'], rule['triage_category'])
                }

    @staticmethod
    def filter(data):
        return ((item[1][0], item[0], item[1][1]) for item in data)


class SixMonths:
    '''
    Table 2 - Rules That Have Not Triggered in the Last 6 Months

    There are rules on your system that have not triggered in at least 6 months. There are no
    detections in the system that are affected by these rules. The behavior may no longer be
    expected on your network or the rule has been consolidated elsewhere.
    '''
    name = 'six_months'
    columns = ['2_detection_name', '2_id', '2_rule_name']
    # fields = ['created_timestamp', 'last_timestamp', 'id', 'detection', 'triage_category']
    fields = None

    @staticmethod
    def extract(rule):
        '''
        Check if it was created more than 6 months ago
        '''
        created_date = datetime.strptime(
            (rule['created_timestamp'])[:10], '%Y-%m-%d'
        )
        if created_date <= SIX_MONTHS_AGO:
            datestr = rule['last_timestamp']
            if datestr is None:
                return {rule['id']: (rule['detection'], rule['triage_category'])}
            else:
                triggered_date = datetime.strptime(datestr[:10], '%Y-%m-%d')
                # Has it been triggered in the last 6 months?
                if triggered_date <= SIX_MONTHS_AGO:
                    return {rule['id']: (rule['detection'], rule['triage_category'])}

    @staticmethod
    def filter(data):
        return ((item[1][0], item[0], item[1][1]) for item in data)


class Whitelist:
    '''
    Table 12 - Whitelist
    Check if there are any whitelist detections
    '''
    name = 'whitelist'
    columns = ['12_rule_name', '12_id']
    # fields = ['is_whitelist', 'id', 'triage_category']
    fields = None

    @staticmethod
    def extract(rule):
        if rule['is_whitelist']:
            return {rule['id']: rule['triage_category']}

    @staticmethod
    def filter(data):
        return ((item[1], item[0]) for item in data)


class AnyAny:
    '''
    Table 13 - Any / Any
    Check for unsafe Triage Filters that Trigger on ANY Source and ANY Destination
    '''
    name = 'any_any'
    columns = ['13_rule_name', '13_id']
    # fields = ['source_conditions', 'additional_conditions', 'id', 'triage_category']
    fields = None

    @staticmethod
    def extract(rule):
        if not rule['source_conditions'] and not rule['additional_conditions']:
            return {rule['id']: rule['triage_category']}

    @staticmethod
    def filter(data):
        return ((item[1], item[0]) for item in data)


RULE_CSV_FILES = [ThreeMonths, SixMonths, Whitelist, AnyAny]


class MarkAsCustom:
    '''
    Table 3 - Mark as Custom with Same Names, Rule Creation may be Beneficial (Past Month)

    These detections were triaged through one time “Mark as Custom”. This can be highly useful for
    behaviors you understand are authorized but want to be alerted upon. This table may however
    identify a rule that you want to implement. “Mark as Custom” does not affect model learnings
    and detections triaged this way may continue to arise.

    Status: Working
    '''
    name = 'mark_as_custom'
    columns = ['3_count', '3_detection_name', '3_rule_name']
    fields = ['is_marked_custom', 'detection_type',
              'custom_detection', 'last_timestamp']

    @staticmethod
    def extract(detection):
        if (
            detection['is_marked_custom']
            and datetime.strptime(
                (detection['last_timestamp'])[:10], '%Y-%m-%d'
            )
            >= ONE_MONTH_AGO
        ):
            yield (detection['detection_type'], detection['custom_detection'])

    @staticmethod
    def filter(data):
        '''
        Enumerate the dictionary of detections marked as custom, return where entries > 1
        since these are recurring Marked as Custom and not one-offs
        '''
        return ((item[1], item[0][0], item[0][1]) for item in data if item[1] > 1)


class NotTriaged:
    '''
    Table 4 - Currently Active Detections Not Triaged by Rule

    These are the detections currently active in Detect and contributing to Host Score.

    Status: Working
    '''
    name = 'not_triaged'
    columns = ['4_count', '4_detection_type']
    fields = ['triage_rule_id', 'detection_type']

    @staticmethod
    def extract(detection):
        if not_triaged(detection):
            yield detection['detection_type']

    @staticmethod
    def filter(data):
        return (
            reversed(item)
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)
        )


class All:
    '''
    Table 5 - Currently Active Detections Including Triaged

    These are all active detections in Detect, including those not contributing to Host Score.
    This may help identify improperly scoped rules.

    Status: Working
    '''
    name = 'all'
    columns = ['5_count', '5_detection_type']
    fields = ['detection_type']

    @staticmethod
    def extract(detection):
        yield detection['detection_type']

    @staticmethod
    def filter(data):
        return (
            reversed(item)
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)
        )


class Source:
    '''
    Table 6 - Top 50 Source IPs of Currently Active Detection Type Not Caught by a Triage Rule

    This table helps identify your noisiest machines on the network. This can either indicate a
    compromise or ongoing and expected behavior. In the latter case, one or more Custom Filter can
    usually be created. This table is expected to be fewer than 50 entries if there are fewer than
    50 hosts with active detections.

    Status: Working
    '''
    name = 'source'
    columns = ['6_count', '6_source_ip']
    fields = ['triage_rule_id', 'src_ip']

    @staticmethod
    def extract(detection):
        if not_triaged(detection) and detection['src_ip']:
            yield detection['src_ip']

    @staticmethod
    def filter(data):
        return (
            reversed(item)
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class SourceType:
    '''
    Table 7 - Top 50 Source IPs Divided by Active Detection Type Not Caught by a Triage Rule
    This table helps identify your noisiest machines on the network by detection type. This
    usually indicated an ongoing and expected behavior. One or more Customer Filter can usually be
    created. This table is expected to be fewer than 50 entries if there are fewer than 50 hosts
    with active detections.

    Status: Working
    '''
    name = 'source_type'
    columns = ['7_count', '7_detection_type', '7_source_ip']
    fields = ['triage_rule_id', 'src_ip', 'detection_type']

    @staticmethod
    def extract(detection):
        if not_triaged(detection) and detection['src_ip']:
            yield (detection['detection_type'], detection['src_ip'])

    @staticmethod
    def filter(data):
        return (
            (item[1], item[0][0], item[0][1])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class Destination:
    '''
    Table 8 -Top 50 Destination Domains Divided by Active Detection Type Not Caught by a Triage Rule

    This table helps identify the most common destination domains of your active detections.
    This usually indicates a common behavior on your network that can be triaged on your system.
    Common destinations include SaaS, and commonly used internal systems. This table is expected to
    be fewer than 50 entries if there are fewer than 50 unique destination domains.

    '''

    name = 'destination'
    columns = [
        '8_count',
        '8_detection_type',
        '8_destination_domain',
        '8_destination_port',
    ]
    fields = ['triage_rule_id', 'detection_type', 'grouped_details']

    @staticmethod
    # TODO: this is throwing a KeyError on VTIM, due to no target_domains. should we exclude or fix?
    def extract(detection):
        # TODO: make this a case, break out VTIM, Hidden HTTPS Tunnel, etc
        if (
            not_triaged(detection)

            # Below needs to be filtered from the intital search
            and detection['detection_type'] != 'Data Gathering'
            and detection['detection_type'] != 'File Share Enumeration'
            and detection['detection_type'] != 'Internal Stage Loader'
            and detection['detection_type'] != 'Kerberos Brute-Sweep'
            and detection['detection_type'] != 'Port Scan'
            and detection['detection_type'] != 'RDP Recon'
            and detection['detection_type'] != 'RPC Recon'
            and detection['detection_type'] != 'RPC Targeted Recon'
            and detection['detection_type'] != 'SMB Account Scan'
            and detection['detection_type'] != 'SMB Brute-Force'
            and detection['detection_type'] != 'Suspicious Admin'
            and detection['detection_type'] != 'Suspicious Remote Desktop'

            # VTIM throws a keyError due to no target_domain, will need to handle
            # differently
        ):
            domains_ports = []
            # C&C:Hidden HTTPS Tunnel - detail['target_domains'][0]
            # C&C:Hidden HTTPS Tunnel - detail['dst_ports'][0]
            # Exfil:Smash and Grab -
            # Info:Novel External Destination Port - detection['summary']['protocol_ports']
            # Info:Novel External Destination Port - detection['summary']['target_domains']
            # Exfil:Data Smuggler - detection['summary']['dst_ports']
            # Exfil:Data Smuggler - detection['summary']['dst_ips']

            for detail in detection['grouped_details']:
                try:
                    domains_ports.append(
                        (detail['target_domains'][0], detail['dst_ports'][0])
                    )
                except KeyError as my_error:
                    logging.error('A KeyError occured while gathering data for detection with id: '
                                  '%d. %s', detection['id'], my_error)
                    logging.debug('Detection Details | Category | %s | Detection | %s',
                                    detection['category'],detection['detection'])

            for domain_port in domains_ports:
                yield (detection['detection_type'], domain_port[0], domain_port[1])

    @staticmethod
    def filter(data):
        return (
            (item[1], item[0][0], item[0][1], item[0][2])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class SDA:
    '''
    Table 9 - Top 50 Destination Domain Requests for Suspect Domain Activity

    This tables identifies the most common suspicious domains detected on your network. Large
    detection counts may indicate a large-scale campaign. This table is expected to be fewer than
    50 entries if there are fewer than 50 unique destination domains.
    '''
    name = 'sda'
    columns = ['9_count', '9_detection_type',
               '9_destination_domain', '9_response']
    fields = ['detection_type', 'grouped_details']

    @staticmethod
    def extract(detection):
        '''
        Get Suspect Domain Activity Detections
        '''
        if detection['detection_type'] == 'Suspect Domain Activity':
            for detail in detection['grouped_details']:
                for domain in detail['target_domains']:
                    if detail['dns_response'] is None:
                        detail['dns_response'] = 'N/A'

                    if domain and detail['dns_response']:
                        yield (detection['detection_type'], domain, detail['dns_response'])

    @staticmethod
    def filter(data):

        return (
            (item[1], item[0][0], item[0][1], item[0][2])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class DestIP:
    '''
    Table 10 - Top 50 Destination IPs Divided by Active Detection Type Not Caught by a Triage Rule

    This table identified the most common destination IPs detected on your network. Large detection
    counts may indicate an expected behavior or misconfiguration. This table is expected to be fewer
    than 50 entries if there are fewer than 50 unique destination IPs.
    '''
    name = 'dest_ip'
    columns = ['10_count', '10_detection_type', '10_destination_ip']
    fields = None

    @staticmethod
    def extract(detection):
        if not_triaged(detection):
            ips = set()
            ips.update(get_all_values(detection, ('dst_ip', 'dst_ips')))
            for ip_addr in ips:
                yield (detection['detection_type'], ip_addr)

    @staticmethod
    def filter(data):
        return (
            (item[1], item[0][0], item[0][1])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class DestPort:
    '''
    Table 11 - Top 50 Destination Ports by Detection Type Not Caught by a Triage Rule

    This table identifies the most common destination ports by detection type. Large detection
    counts may indicate an expected behavior. This table is expected to be fewer than 50 entries if
    there are fewer than 50 active detections.
    '''
    name = 'dest_port'
    columns = ['11_count', '11_detection_type', '11_destination_port']
    fields = None

    @staticmethod
    def extract(detection):
        if not_triaged(detection):
            ports = set()
            ports.update(get_all_values(detection, ('dst_port', 'dst_ports')))
            for port in ports:
                yield (detection['detection_type'], port)

    @staticmethod
    def filter(data):
        return (
            (item[1], item[0][0], item[0][1])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


class DomainController:
    '''
    Grab Domain Controllers
    '''
    name = 'domain_controllers'
    columns = ['10_hostname', '10_src_ip']
    fields = None

    @staticmethod
    def extract(detection):
        print(detection)

    @staticmethod
    def filter(data):
        return (
            (item[1], item[0][0], item[0][1])
            for item in sorted(data, key=lambda kv: (kv[1], kv[0]), reverse=True)[
                :LIST_SIZE
            ]
        )


DETECTION_CSV_FILES = [
    MarkAsCustom,
    NotTriaged,
    All,
    Source,
    SourceType,
    Destination,
    SDA,
    DestIP,
    DestPort
]

ALL_CSV_FILES = DETECTION_CSV_FILES + RULE_CSV_FILES + GROUP_CSV_FILES


def get_all_values(json, key_names):
    '''
    recursively search through entire json object for matching keys,
    return a set of paired values
    '''
    results = set()
    for key, value in json.items():
        if key in key_names:
            if isinstance(value, list):
                results.update(value)
            else:
                results.add(value)
        elif isinstance(value, dict):
            results.update(get_all_values(value, key_names))
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                for val in value:
                    results.update(get_all_values(val, key_names))
    return results
