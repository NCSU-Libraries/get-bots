import re
from collections import defaultdict, Counter
import argparse
from datetime import datetime
import urllib.parse
import json
import numpy as np
import pandas as pd
import ipaddress
from intervaltree import IntervalTree

ASN_FILE = 'data/asn.csv'

def get_bots_from_file(log_file, rails):
    # Read log lines from the specified file
    with open(log_file, "r") as file:
        log_lines = file.readlines()
    return process_log_lines(log_lines, rails)

def process_log_lines(log_lines, rails):
    ip_data = defaultdict(lambda: {
        'count': 0, 
        'user_agents': set(), 
        'requests': [], 
        'normalized_requests': [],
        'first_hit': None, 
        'last_hit': None
    })

    ip_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    user_agent_regex = re.compile(r'"([^"]+)"$')

    if rails:
        request_pattern_regex = re.compile(r'Started (GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) "(.*?)"')
        timestamp_regex = re.compile(r'at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})')
    else:
        request_pattern_regex = re.compile(r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP/\d\.\d\"')
        timestamp_regex = re.compile(r'\[(.*?)\]')

    for line in log_lines:
        ip_match = ip_regex.search(line)
        user_agent_match = user_agent_regex.search(line)
        request_pattern_match = request_pattern_regex.search(line)
        timestamp_match = timestamp_regex.search(line)
        if ip_match and request_pattern_match and timestamp_match:
            ip = ip_match.group(1)
            user_agent = user_agent_match.group(1) if user_agent_match else "Unknown"
            request_path = request_pattern_match.group(2)
            timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S %z' if rails else '%d/%b/%Y:%H:%M:%S %z')

            normalized_request = normalize_request(request_path)

            ip_data[ip]['count'] += 1
            ip_data[ip]['user_agents'].add(user_agent)
            ip_data[ip]['requests'].append(request_path)
            ip_data[ip]['normalized_requests'].append(normalized_request)

            if ip_data[ip]['first_hit'] is None or timestamp < ip_data[ip]['first_hit']:
                ip_data[ip]['first_hit'] = timestamp
            if ip_data[ip]['last_hit'] is None or timestamp > ip_data[ip]['last_hit']:
                ip_data[ip]['last_hit'] = timestamp

    # Convert ip_data to a list of dictionaries
    output_data = []
    for ip, data in ip_data.items():
        # Determine the most common normalized request pattern for each IP address
        request_counter = Counter(data['normalized_requests'])
        most_common_request, most_common_request_count = request_counter.most_common(1)[0]
        data['most_common_request'] = most_common_request
        data['most_common_request_count'] = most_common_request_count
        user_agents = list(data['user_agents'])
        output_data.append({
            'ip': ip,
            'count': data['count'],
            'user_agents': user_agents,
            'most_common_request': data['most_common_request'],
            'most_common_request_count': data['most_common_request_count'],
            'first_hit': data['first_hit'],
            'last_hit': data['last_hit']
        })

    return output_data

def normalize_request(request):
    """
    Extracts the request path and query parameters, then normalizes them
    by replacing values with 'X' and sorting parameters.
    """
    try:
        parsed_url = urllib.parse.urlparse(request)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Create a normalized version with sorted parameter names
        normalized_query = "&".join(sorted(f"{key}=X" for key in query_params.keys()))
        
        return f"{parsed_url.path}?{normalized_query}" if normalized_query else parsed_url.path
    except Exception as e:
        return request

def load_asn_data(file_path):
    asn_data = pd.read_csv(file_path)
    asn_data['start_ip'] = asn_data['start_ip'].apply(ipaddress.ip_address)
    asn_data['end_ip'] = asn_data['end_ip'].apply(ipaddress.ip_address)
    return asn_data

def build_interval_tree(asn_data):
    interval_tree = IntervalTree()
    for _, row in asn_data.iterrows():
        if row['start_ip'].version == 6:
            continue  # Skip IPv6 ranges
        interval_tree[row['start_ip']:row['end_ip']] = row['asn']
    return interval_tree

def build_asn_info(asn_data):
    asn_info = {}
    for _, row in asn_data.iterrows():
        asn_info[row['asn']] = (str(row['name']), str(row['domain']))
    return asn_info

def find_ip_range(ip, interval_tree):
    ip_addr = ipaddress.ip_address(ip)
    if ip_addr.version == 6:
        return None, None  # Skip IPv6 addresses
    intervals = interval_tree[ip_addr]
    if intervals:
        interval = intervals.pop()
        return f"{interval.begin}-{interval.end}", interval.data
    return None, None

def find_smallest_subnet(ip1, ip2):
    ip1 = ipaddress.ip_address(ip1)
    ip2 = ipaddress.ip_address(ip2)
    # Ensure ip1 is the lower IP and ip2 is the higher IP
    if ip1 > ip2:
        ip1, ip2 = ip2, ip1
    # Find the smallest subnet that includes both IPs
    for prefix_length in range(32, -1, -1):
        network = ipaddress.ip_network(f"{ip1}/{prefix_length}", strict=False)
        if ip2 in network:
            return network

def process_output_data(ip_data, interval_tree, asn_info, output_format=None):
    # Group IP addresses by IP range and calculate total requests per range
    range_hits = defaultdict(list)
    range_requests = defaultdict(int)
    range_lowest_ip = {}
    range_highest_ip = {}
    range_first_hit = {}
    range_last_hit = {}
    ip_requests = defaultdict(list)
    worst_offenders = {}
    worst_offender_count = {}
    for entry in ip_data:
        ip = entry['ip']
        count = entry['count']
        first_hit = entry['first_hit']
        last_hit = entry['last_hit']
        ip_range, asn = find_ip_range(ip, interval_tree)
        if ip_range:
            range_hits[ip_range].append((ip, asn))
            range_requests[ip_range] += count
            ip_requests[ip_range].append(count)
            if ip_range not in range_lowest_ip or ipaddress.ip_address(ip) < ipaddress.ip_address(range_lowest_ip[ip_range]):
                range_lowest_ip[ip_range] = ip
            if ip_range not in range_highest_ip or ipaddress.ip_address(ip) > ipaddress.ip_address(range_highest_ip[ip_range]):
                range_highest_ip[ip_range] = ip
            if ip_range not in range_first_hit or first_hit < range_first_hit[ip_range]:
                range_first_hit[ip_range] = first_hit
            if ip_range not in range_last_hit or last_hit > range_last_hit[ip_range]:
                range_last_hit[ip_range] = last_hit
            if ip_range not in worst_offenders or count > next(item for item in ip_data if item['ip'] == worst_offenders[ip_range])['count']:
                worst_offenders[ip_range] = ip
                worst_offender_count[ip_range] = count

    # Sort IP ranges by the total number of requests
    sorted_ranges = sorted(range_requests.items(), key=lambda item: item[1], reverse=True)

    # Prepare data for output
    output_data = []
    for ip_range, total_requests in sorted_ranges:
        ips = range_hits[ip_range]
        asns = set(asn for ip, asn in ips)
        lowest_ip = range_lowest_ip[ip_range]
        highest_ip = range_highest_ip[ip_range]
        cidr_range = find_smallest_subnet(lowest_ip, highest_ip)
        total_cidr_ips = cidr_range.num_addresses
        asn_names = ', '.join(asn_info[asn][0] for asn in asns if asn in asn_info)
        asn_domains = ', '.join(asn_info[asn][1] for asn in asns if asn in asn_info)
        requests_per_ip = round(total_requests / len(ips), 2)
        std_dev_requests_per_ip = round(np.std(ip_requests[ip_range]), 2)
        if np.isnan(std_dev_requests_per_ip):
            std_dev_requests_per_ip = 0
        cv_requests_per_ip = round((std_dev_requests_per_ip / requests_per_ip) * 100, 2) if requests_per_ip != 0 else 0
        worst_offender_ip = worst_offenders[ip_range]
        worst_offender_data = next(item for item in ip_data if item['ip'] == worst_offender_ip)
        first_hit = range_first_hit[ip_range]
        last_hit = range_last_hit[ip_range]
        time_range_seconds = (last_hit - first_hit).total_seconds() if first_hit and last_hit else None
        output_data.append({
            'asn_ip_range': ip_range,
            'ip_count': len(ips),
            'total_requests': total_requests,
            'time_range_seconds': time_range_seconds,
            'asn': ', '.join(asns),
            'asn_name': asn_names,
            'asn_domain': asn_domains,
            'lowest_ip_found': lowest_ip,
            'highest_ip_found': highest_ip,
            'cidr_range': str(cidr_range),
            'total_cidr_ips': total_cidr_ips,
            'requests_per_ip': requests_per_ip,
            'std_dev_requests': std_dev_requests_per_ip,
            'variation_coefficient': cv_requests_per_ip,
            'worst_offender': worst_offender_ip,
            'worst_offender_user_agent': list(worst_offender_data['user_agents']),  # Convert set to list for output
            'worst_offenders_request_total': worst_offender_count[ip_range],
            'worst_offender_common_request': worst_offender_data['most_common_request'],
            'worst_offender_common_request_count': worst_offender_data['most_common_request_count'],
            'first_hit': first_hit.strftime('%Y-%m-%d %H:%M:%S %z') if first_hit else None,
            'last_hit': last_hit.strftime('%Y-%m-%d %H:%M:%S %z') if last_hit else None,
            'time_range_seconds': time_range_seconds
        })

    # Print top 10 total_requests to JSON if no output format is specified
    top_10_data = sorted(output_data, key=lambda x: x['total_requests'], reverse=True)[:10]
    if not output_format:
        print(json.dumps(top_10_data, indent=4))
    else:
        # Optionally write full output to CSV or JSON
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_format == 'csv':
            output_df = pd.DataFrame(output_data)
            output_file = f"bot-output_{current_time}.csv"
            output_df.to_csv(output_file, index=False)
        elif output_format == 'json':
            output_file = f"bot-output_{current_time}.json"
            with open(output_file, 'w') as json_file:
                json.dump(output_data, json_file, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Process bot data.')
    parser.add_argument('log_file', type=str, help='The log file containing the output of tail -n 200000')
    parser.add_argument('-r', '--rails', action='store_true', help='Specify if processing a Rails output log')
    parser.add_argument('-o', '--output', choices=['csv', 'json'], help='Specify the output format for the full data')
    args = parser.parse_args()

    ip_data = get_bots_from_file(args.log_file, args.rails)
    asn_data = load_asn_data(ASN_FILE)
    interval_tree = build_interval_tree(asn_data)
    asn_info = build_asn_info(asn_data)
    process_output_data(ip_data, interval_tree, asn_info, args.output)

if __name__ == "__main__":
    main()