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
import yaml

# Load configuration from YAML file
with open('config.yml', 'r') as config_file:
    config = yaml.safe_load(config_file)

ASN_FILE = config['ipinfo_version']['db_file']

def get_bots_from_file(log_file, rails, day=None, stats=None):
    # Read log lines from the specified file
    with open(log_file, "r") as file:
        log_lines = file.readlines()
    return process_log_lines(log_lines, rails, day, stats)


def process_log_lines(log_lines, rails, day=None, stats=None):
    ip_data = defaultdict(lambda: {
        'count': 0, 
        'user_agents': set(), 
        'requests': [], 
        'normalized_requests': [],
        'first_hit': None, 
        'last_hit': None,
        'hit_timestamps': []
    })

    ip_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    
    if stats:
        user_agent_regex = re.compile(r'"([^"]+)"$')

    if rails:
        request_pattern_regex = re.compile(r'Started (GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) "(.*?)"')
        timestamp_regex = re.compile(r'at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})')
    else:
        request_pattern_regex = re.compile(r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP/\d\.\d\"')
        timestamp_regex = re.compile(r'\[(.*?)\]')
    
    first_timestamp = None
    last_timestamp = None

    for line in log_lines:
        if day and day not in line:
            continue
        if rails and "Started" not in line:
            continue
        ip_match = ip_regex.search(line)
        
        if stats:
            user_agent_match = user_agent_regex.search(line)
        else:
            user_agent_match = None
        
        request_pattern_match = request_pattern_regex.search(line)
        timestamp_match = timestamp_regex.search(line)
        
        if ip_match and request_pattern_match and timestamp_match:
            ip = ip_match.group(1)
            if stats:
                user_agent = user_agent_match.group(1) if user_agent_match else "Unknown"
            
            timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S %z' if rails else '%d/%b/%Y:%H:%M:%S %z')

            # Track first and last timestamps
            if first_timestamp is None or timestamp < first_timestamp:
                first_timestamp = timestamp
            if last_timestamp is None or timestamp > last_timestamp:
                last_timestamp = timestamp

            if stats:
                request_path = request_pattern_match.group(2)
                normalized_request = normalize_request(request_path)

            ip_data[ip]['count'] += 1
            
            if stats:
                ip_data[ip]['user_agents'].add(user_agent)
                ip_data[ip]['requests'].append(request_path)
                ip_data[ip]['normalized_requests'].append(normalized_request)

            if ip_data[ip]['first_hit'] is None or timestamp < ip_data[ip]['first_hit']:
                ip_data[ip]['first_hit'] = timestamp
            if ip_data[ip]['last_hit'] is None or timestamp > ip_data[ip]['last_hit']:
                ip_data[ip]['last_hit'] = timestamp
            
            ip_data[ip]['hit_timestamps'].append(timestamp)

    # Convert ip_data to a list of dictionaries
    output_data = convert_ip_data_to_output(ip_data, stats)
    return output_data, first_timestamp, last_timestamp

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


def convert_ip_data_to_output(ip_data, stats=None):
    """
    Converts the ip_data defaultdict to a list of dictionaries for output.
    """
    output_data = []
    
    for ip, data in ip_data.items():
        # Determine the most common normalized request pattern for each IP address
        if stats:
            request_counter = Counter(data['normalized_requests'])
            most_common_request, most_common_request_count = request_counter.most_common(1)[0]
            data['most_common_request'] = most_common_request
            data['most_common_request_count'] = most_common_request_count
            user_agents = list(data['user_agents'])
        else:
            user_agents = None
            data['most_common_request'] = None
            data['most_common_request_count'] = None
        
        output_data.append({
            'ip': ip,
            'count': data['count'],
            'user_agents': user_agents,
            'most_common_request': data['most_common_request'],
            'most_common_request_count': data['most_common_request_count'],
            'first_hit': data['first_hit'],
            'last_hit': data['last_hit'],
            'hit_timestamps': data['hit_timestamps']
        })

    return output_data
    

def load_asn_data(file_path):
    asn_data = pd.read_csv(file_path)
    asn_data['network'] = asn_data['network'].apply(ipaddress.ip_network)
    return asn_data


def build_interval_tree(asn_data):
    interval_tree = IntervalTree()
    for _, row in asn_data.iterrows():
        network = row['network']
        asn = row['asn']
        
        # Skip IPv6 ranges and rows where ASN is null
        if network.version == 6 or pd.isnull(asn):
            continue
        
        interval_tree[network.network_address:network.broadcast_address + 1] = {
            'asn': asn,
            'as_name': row['as_name'],
            'as_domain': row['as_domain'],
            'country': row['country'],
            'network': str(network)
        }

    return interval_tree


def find_ip_range(ip, interval_tree):
    ip_addr = ipaddress.ip_address(ip)
    if ip_addr.version == 6:
        return None, None  # Skip IPv6 addresses
    intervals = interval_tree[ip_addr]
    if intervals:
        interval = intervals.pop()
        data = interval.data
        return data['network'], data['asn'], data['as_name'], data['as_domain'], data['country']
    return None, None, None, None, None


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


def summarize_address_range(start_ip, end_ip):
    ip1 = ipaddress.ip_address(start_ip)
    ip2 = ipaddress.ip_address(end_ip)

    if ip1 > ip2:
        ip1, ip2 = ip2, ip1
    
    cidr_summary = list(ipaddress.summarize_address_range(ip1, ip2))
    cidr_list = [str(cidr) for cidr in cidr_summary]
    return cidr_list
        

def generate_output_data(ip_data, interval_tree, first_timestamp, last_timestamp, output_format=None, groupby=None, stats=None):
    if groupby == 'asn':
        group_by_asn(ip_data, interval_tree, first_timestamp, last_timestamp, output_format, stats)
    elif groupby == 'ip_range':
        process_by_ip_range(ip_data, interval_tree, first_timestamp, last_timestamp, output_format, stats)


def process_by_ip_range(ip_data, interval_tree, first_timestamp, last_timestamp, output_format=None, stats=None):
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
    all_requests = 0
    all_ips = 0
    total_US_requests = 0
    total_US_ips = 0
    total_nonUS_requests = 0
    total_nonUS_ips = 0
    hourly_buckets = defaultdict(lambda: defaultdict(int))
    for entry in ip_data:
        ip = entry['ip']
        count = entry['count']
        first_hit = entry['first_hit']
        last_hit = entry['last_hit']
        ip_range, asn, as_name, as_domain, country = find_ip_range(ip, interval_tree)
        if ip_range:
            range_hits[ip_range].append((ip, asn, as_name, as_domain, country))
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
            if ip_range not in worst_offenders or count > worst_offender_count[ip_range]:
                worst_offenders[ip_range] = ip
                worst_offender_count[ip_range] = count
            for timestamp in entry['hit_timestamps']:
                # store in an hourly bucket for each ip range
                hour_key = timestamp.strftime('%Y-%m-%d %H:00:00 %z')
                hourly_buckets[ip_range][hour_key] += 1
            
        all_requests += count
        all_ips += 1
        
        if country == 'United States':
            total_US_requests += count
            total_US_ips += 1
        else:
            total_nonUS_requests += count
            total_nonUS_ips += 1
        
    # Sort IP ranges by the total number of requests
    sorted_ranges = sorted(range_requests.items(), key=lambda item: item[1], reverse=True)

    # Prepare data for output
    output_data = []

    for ip_range, total_requests in sorted_ranges:
        ips = range_hits[ip_range]
        asns = set(asn for ip, asn, as_name, as_domain, country in ips)
        as_names = ', '.join({as_name for ip, asn, as_name, as_domain, country in ips if pd.notna(as_name)})
        as_domains = ', '.join({as_domain for ip, asn, as_name, as_domain, country in ips if pd.notna(as_domain)})
        countries = set(country for ip, asn, as_name, as_domain, country in ips)
        countries = ', '.join(countries)
        lowest_ip = range_lowest_ip[ip_range]
        highest_ip = range_highest_ip[ip_range]
        cidr_range = find_smallest_subnet(lowest_ip, highest_ip)
        total_cidr_ips = cidr_range.num_addresses
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
        hourly_hits = hourly_buckets[ip_range]          
        if hourly_hits:                                 
            peak_hour, peak_count = max(hourly_hits.items(), key=lambda kv: kv[1])
        else:
            peak_hour, peak_count = None, 0
        if stats:
          output_data.append({
              'asn_ip_range': ip_range,
              'ip_count': len(ips),
              'total_requests': total_requests,
              'time_range_seconds': time_range_seconds,
              'peak_hour': peak_hour,      
              'peak_hour_hits': peak_count,     
              'asn': ', '.join(asns),
              'as_name': as_names,
              'as_domain': as_domains,
              'countries': countries,
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
        else:
          output_data.append({
              'asn_ip_range': ip_range,
              'ip_count': len(ips),
              'total_requests': total_requests,
              'time_range_seconds': time_range_seconds,
              'peak_hour': peak_hour,      
              'peak_hour_hits': peak_count,
              'asn': ', '.join(asns),
              'as_name': as_names,
              'as_domain': as_domains,
              'countries': countries,
              'lowest_ip_found': lowest_ip,
              'highest_ip_found': highest_ip,
              'cidr_range': str(cidr_range),
              'total_cidr_ips': total_cidr_ips,
              'requests_per_ip': requests_per_ip,
              'first_hit': first_hit.strftime('%Y-%m-%d %H:%M:%S %z') if first_hit else None,
              'last_hit': last_hit.strftime('%Y-%m-%d %H:%M:%S %z') if last_hit else None
          })

    # Print top 10 total_requests to JSON if no output format is specified
    top_10_data = sorted(output_data, key=lambda x: x['total_requests'], reverse=True)[:10]
    if not output_format:
        total_time_hours = (last_timestamp - first_timestamp).total_seconds() / 3600 if first_timestamp and last_timestamp else None

        total_data = {
            'total_requests': all_requests,
            'total_ips': all_ips,
            'total_time_hours': f"{total_time_hours:.2f}" if total_time_hours else None,
            'first_timestamp': first_timestamp.strftime('%Y-%m-%d %H:%M:%S %z') if first_timestamp else None,
            'last_timestamp': last_timestamp.strftime('%Y-%m-%d %H:%M:%S %z') if last_timestamp else None,
            'total_US_requests': total_US_requests,
            'total_US_ips': total_US_ips,
            'total_nonUS_requests': total_nonUS_requests,
            'total_nonUS_ips': total_nonUS_ips,
            'output_data': top_10_data
        }
        print(json.dumps(total_data, indent=4))
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


def group_by_asn(ip_data, interval_tree, first_timestamp, last_timestamp, output_format=None, stats=None):
    range_hits = defaultdict(list)
    range_requests = defaultdict(int)
    ip_requests = defaultdict(list)
    range_lowest_ip = {}
    range_highest_ip = {}
    range_first_hit = {}
    range_last_hit = {}
    worst_offenders = {}
    all_requests = 0
    all_ips = 0
    total_US_requests = 0
    total_US_ips = 0
    total_nonUS_requests = 0
    total_nonUS_ips = 0
    country_breakdown = {}
    country_subnets = defaultdict(set)
    asn_hourly_buckets = defaultdict(lambda: defaultdict(int))
    for entry in ip_data:
        ip = entry['ip']
        # Skip private IPs
        if ip.startswith('10.'):
            continue
        count = entry['count']
        first_hit = entry['first_hit']
        last_hit = entry['last_hit']
        ip_range, asn, as_name, as_domain, country = find_ip_range(ip, interval_tree)
        if ip_range:
            range_hits[ip_range].append((ip, asn, as_name, as_domain, country))
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
            if ip_range not in worst_offenders or count > worst_offenders[ip_range]['count']:
                worst_offenders[ip_range] = {'ip' : ip, 'count': count}
            for timestamp in entry['hit_timestamps']:
                # store in an hourly bucket for each ip range
                hour_key = timestamp.strftime('%Y-%m-%d %H:00:00 %z')
                asn_hourly_buckets[asn][hour_key] += 1
        all_requests += count
        all_ips += 1
        
        if country == 'United States':
            total_US_requests += count
            total_US_ips += 1
        else:
            total_nonUS_requests += count
            total_nonUS_ips += 1
        
        if country not in country_breakdown:
            country_breakdown[country] = {'requests': count, 'IPs': 1}
        else:
            country_breakdown[country]['requests'] += count
            country_breakdown[country]['IPs'] += 1
        
        country_subnets[country].add(ip_range)

    asn_data = defaultdict(lambda: {
        'total_requests': 0,
        'total_ips': 0,
        "time_range_minutes": 0,
        "start_time": None,
        "end_time": None,
        'as_name': set(),
        'as_domain': set(),
        'cidr_ranges': defaultdict(lambda: {'ip_count': 0, 'total_requests': 0, 'country': '', 'ip_range':  ''})
    })

    sorted_ranges = sorted(range_requests.items(), key=lambda item: item[1], reverse=True)

    for ip_range, total_requests in sorted_ranges:
        ips = range_hits[ip_range]
        asns = set(asn for ip, asn, as_name, as_domain, country in ips)
        as_names = ', '.join({as_name for ip, asn, as_name, as_domain, country in ips if pd.notna(as_name)})
        as_domains = ', '.join({as_domain for ip, asn, as_name, as_domain, country in ips if pd.notna(as_domain)})
        countries = set(country for ip, asn, as_name, as_domain, country in ips)
        countries = ', '.join(countries)
        lowest_ip = range_lowest_ip[ip_range]
        highest_ip = range_highest_ip[ip_range]
        cidr_range = find_smallest_subnet(lowest_ip, highest_ip)
        cidr_range_small = str(cidr_range)

        # Update ASN data
        for asn in asns:
            asn_data[asn]['total_requests'] += total_requests
            asn_data[asn]['total_ips'] += len(ips)
            if asn_data[asn]['start_time'] is None or range_first_hit[ip_range] < asn_data[asn]['start_time']:
                asn_data[asn]['start_time'] = range_first_hit[ip_range]
            if asn_data[asn]['end_time'] is None or range_last_hit[ip_range] > asn_data[asn]['end_time']:
                asn_data[asn]['end_time'] = range_last_hit[ip_range]
            asn_data[asn]['cidr_ranges'][ip_range]['ip_count'] += len(ips)
            asn_data[asn]['cidr_ranges'][ip_range]['total_requests'] = total_requests
            asn_data[asn]['cidr_ranges'][ip_range]['country'] = countries
            asn_data[asn]['cidr_ranges'][ip_range]['subnet_within_subnet'] = cidr_range_small
            asn_data[asn]['cidr_ranges'][ip_range]['worst_offender'] = worst_offenders[ip_range]['ip'] if ip_range in worst_offenders else None
            asn_data[asn]['cidr_ranges'][ip_range]['worst_offender_count'] = worst_offenders[ip_range]['count'] if ip_range in worst_offenders else 0

            if pd.notna(as_name):
                asn_data[asn]['as_name'].add(as_names)
            if pd.notna(as_domain):
                asn_data[asn]['as_domain'].add(as_domains)
            
            # Calculate time range in hours for each ASN
            if asn_data[asn]['start_time'] and asn_data[asn]['end_time']:
                time_range = (asn_data[asn]['end_time'] - asn_data[asn]['start_time']).total_seconds() / 3600
                asn_data[asn]['time_range_hours'] = time_range
    
    # Prepare ASN grouped data for output
    asn_output_data = []

    for asn, data in asn_data.items():
        cidr_ranges_with_data = {
            cidr: {
                'ip_count': values['ip_count'], 
                'total_requests': values['total_requests'], 
                'country': values['country'], 
                'subnet_within_subnet': values['subnet_within_subnet'],
                'worst_offender': values['worst_offender'],
                'worst_offender_count': values['worst_offender_count']
                #'cidr_list': values['cidr_list']
            } 
            for cidr, values in data['cidr_ranges'].items()
        }
        hours_for_asn = asn_hourly_buckets[asn] 
        if hours_for_asn:
                peak_hour, peak_hits = max(hours_for_asn.items(), key=lambda kv: kv[1])
        else:
            peak_hour, peak_hits = None, 0
        
        asn_output_data.append({
            'ASN': asn,
            'AS Names': list(data['as_name']),
            'AS Domains': list(data['as_domain']),
            'Total Requests': data['total_requests'],
            'Total IPs': data['total_ips'],
            'Time Range (hours)': f"{data['time_range_hours']:.2f}",
            'Peak Hour': peak_hour,
            'Peak Hour Hits': peak_hits,
            'Start Time': data['start_time'].strftime('%Y-%m-%d %H:%M:%S %z') if data['start_time'] else None,
            'End Time': data['end_time'].strftime('%Y-%m-%d %H:%M:%S %z') if data['end_time'] else None,
            'Subnet count': len(cidr_ranges_with_data),
            'Subnets': list(cidr_ranges_with_data.keys()),
            'Detailed Subnet Info': cidr_ranges_with_data
        })

    # Sort ASN data by total requests
    asn_output_data = sorted(asn_output_data, key=lambda x: x['Total Requests'], reverse=True)
    
    # calculate country breakdown percentages
    for country in country_breakdown:
      percent_requests = round((country_breakdown[country]['requests'] / all_requests) * 100, 2)
      country_breakdown[country]['%_total_requests'] = percent_requests
      country_breakdown[country]['unique_subnets'] = len(country_subnets[country])

    country_breakdown = sorted(country_breakdown.items(), key=lambda x: x[1]['requests'], reverse=True)

    # Default to top 10 if no output format is specified
    if not output_format:
        asn_output_data = asn_output_data
        total_time_hours = (last_timestamp - first_timestamp).total_seconds() / 3600 if first_timestamp and last_timestamp else None
        
        total_data = {
            'Total Requests': all_requests,
            'Total IPs': all_ips,
            'Total Time (hours)': f"{total_time_hours:.2f}" if total_time_hours else None,
            'First Timestamp': first_timestamp.strftime('%Y-%m-%d %H:%M:%S %z') if first_timestamp else None,
            'Last Timestamp': last_timestamp.strftime('%Y-%m-%d %H:%M:%S %z') if last_timestamp else None,
            'Total US Requests': total_US_requests,
            'US Request %': round((total_US_requests / all_requests) * 100, 2),
            'Total US IPs': total_US_ips,
            'Total Non-US Requests': total_nonUS_requests,
            'Non-US Request %': round((total_nonUS_requests / all_requests) * 100, 2),
            'Total Non-US IPs': total_nonUS_ips,
            'Country Breakdown': country_breakdown,
            'ASN Data': asn_output_data 
        }

        print(json.dumps(total_data, indent=4))
    else:
        # Optionally write full output to CSV or JSON
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_format == 'csv':
            output_df = pd.DataFrame(asn_output_data)
            output_file = f"bot-asn-output_{current_time}.csv"
            output_df.to_csv(output_file, index=False)
        elif output_format == 'json':
            output_file = f"bot-asn-output_{current_time}.json"
            with open(output_file, 'w') as json_file:
               json.dump(asn_output_data, json_file, indent=4)
            print(json.dumps(asn_output_data, indent=4))

def main():
    parser = argparse.ArgumentParser(description='Process bot data.')
    parser.add_argument('log_file', type=str, help='The log file to process')
    parser.add_argument('-r', '--rails', action='store_true', help='Specify if processing a Rails output log')
    parser.add_argument('-o', '--output', choices=['csv', 'json'], help='Specify an output file format for the full data')
    parser.add_argument('-g', '--groupby', choices=['asn', 'ip_range'], default='asn', help='Group data by ASN or individual ip ranges within that ASN')
    parser.add_argument('-d', '--day', type=str, help='Specify the day to filter logs (default format: dd/MMM/yyyy; rails format: yyyy-mm-dd)', default=None)
    parser.add_argument('-s', '--stats', action='store_true', help='Specify if you want to include verbose stats in the output')
    args = parser.parse_args()
    ip_data, first_timestamp, last_timestamp = get_bots_from_file(args.log_file, args.rails, args.day, args.stats)
    asn_data = load_asn_data(ASN_FILE)
    interval_tree = build_interval_tree(asn_data)
    generate_output_data(ip_data, interval_tree, first_timestamp, last_timestamp, args.output, args.groupby, args.stats)

if __name__ == "__main__":
    main()