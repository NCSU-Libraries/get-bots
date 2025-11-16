This project processes the output of Apache logs (Combined format) logs to identify bots based on ASN ranges from ASN data downloaded from [IPinfo.io](https://ipinfo.io/account/data-downloads). 


## Usage

```
python get_bots.py accessfile [-r] [-o output-format]
```
- accessfile: path to your http access or rails log
- r: process a rails log (log level must be set to debug)
- o: this option allows you to dump entire data output into a csv file or json file (specify json or csv as the output format). 
- g: group data by ASN or by smaller IP ranges within an ASN (by default will group by total ASN). Accepted inputs: `ip_range`; `asn`
- d: provide a date value if your log file contains requests for several days but you just want data output for one day. Format must be `dd/MMM/yyyy` if processing Apache logs and `yyyy-mm-dd` if processing rails logs.
- s: this will generate additional statistical analysis (currently only works when grouping data by IP range subnets)

Basic example:
```
python get_bots.py secure-access.log  # secure-access.log usually found at /var/log/httpd/$(hostname)-secure_access_ssl.log
```
Example of processing a rails log and sending the output to a csv file:
```
python get_bots.py production.log -r -o csv
```
## Output data

The script defaults to outputting the results in JSON. This default output consists of overview data, a country by country breakdown, a break down for each ASN, and then a further breakdown of each subnet within that ASN. By specifying '-o csv' or '-o json' the script will output into a CSV or JSON file. If you choose to output into a CSV file, the overview data and country by country breakdown is not included, because of the limited flexibility of CSV. The following is an example of data collected by default:
```
{
    "Total Requests": 216742,
    "Total IPs": 84361,
    "Total Time (hours)": "80.22",
    "First Timestamp": "2025-06-29 03:18:02 -0400",
    "Last Timestamp": "2025-07-02 11:31:06 -0400",
    "Total US Requests": 63712,
    "US Request %": 29.4,
    "Total US IPs": 8201,
    "Total Non-US Requests": 153030,
    "Non-US Request %": 70.6,
    "Total Non-US IPs": 76160,
    "Country Breakdown": [
        [
            "United States",
            {
                "requests": 63712,
                "ips": 8201,
                "percent_requests": 29.4,
                "unique_subnets": 1652
            }
        ],
        [
            "China",
            {
                "requests": 45361,
                "ips": 18890,
                "percent_requests": 20.93,
                "unique_subnets": 1945
            }
        ]
  .....
    ],
    "ASN Data": [
          {
            "ASN": "AS559",
            "AS Names": [
                "SWITCH"
            ],
            "AS Domains": [
                "switch.ch"
            ],
            "Total Requests": 239,
            "Total IPs": 2,
            "Time Range (hours)": "26.49",
            "Peak Hour": "2025-07-02 03:00:00 -0400",
            "Peak Hour Hits": 24,
            "Start Time": "2025-07-01 08:53:35 -0400",
            "End Time": "2025-07-02 11:22:58 -0400",
            "Subnet count": 2,
            "Subnets": [
                "192.26.28.0/22",
                "130.92.0.0/16"
            ],
            "Detailed Subnet Info": {
                "192.26.28.0/22": {
                    "ip_count": 1,
                    "total_requests": 234,
                    "country": "Switzerland",
                    "subnet_within_subnet": "192.26.29.232/32",
                    "worst_offender": "192.26.29.232",
                    "worst_offender_count": 234
                },
                "130.92.0.0/16": {
                    "ip_count": 1,
                    "total_requests": 5,
                    "country": "Switzerland",
                    "subnet_within_subnet": "130.92.201.65/32",
                    "worst_offender": "130.92.201.65",
                    "worst_offender_count": 5
                }
            }
        },     
  ....
    ]
}
```
If you choose to group by ip_range the data will output like the following. Additional data on user agent strings and common request patterns can be captured by adding the `-s` input option:
```
{
        "asn_ip_range": "20.160.0.0-20.175.255.255",
        "ip_count": 2,
        "total_requests": 978,
        "time_range_seconds": 18360.0,
        "asn": "AS8075",
        "asn_name": "Microsoft Corporation",
        "asn_domain": "microsoft.com",
        "lowest_ip_found": "20.161.75.216",
        "highest_ip_found": "20.171.207.152",
        "cidr_range": "20.160.0.0/12",
        "total_cidr_ips": 1048576,
        "requests_per_ip": 489.0,
        "std_dev_requests": 487.0,
        "variation_coefficient": 99.59,
        "worst_offender": "20.171.207.152",
        "worst_offender_user_agents": [
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
        ],
        "worst_offenders_request_total": 976,
        "worst_offender_common_request": "/collections/?f[topic_facet][]=X&f[work_facet][]=X&per_page=X",
        "worst_offender_common_request_count": 685,
        "first_hit": "2025-02-24 01:38:37 -0500",
        "last_hit": "2025-02-24 06:44:37 -0500"
    }
```
Currently, breakdown by country is only available in the default group by ASN option.

## requirements/venv setup
```
# sync project with uv
uv sync
```

## Managing output data

The default output data is a little unwieldy and can be quite long. It is best to output it into a JSON file to read over. You can also use `jq` to analyze the data as well.

For example, the default output of `get_bots.py` will output a list of subnet CIDRs for each ASN. To grab those CIDRS you can pipe the output into a `jq` expression like the following, replacing the '0' in the `ASN Data` array with whichever ASN you need (the number represents the ranking of the ASN according to most traffic, 0 having the most, 1 having the second most etc.) 
```
 jq -r '.["ASN Data"][0].Subnets[]'
``` 
This will output a list of subnets for blocking purposes. Here's the full script using uv:
```
uv run get_bots.py example_http_access_log.log | jq -r '.["ASN Data"][0].Subnets[]'
```

## warnings
This code has not been fully tested or vetted, especially the rails output option.  

## acknowledgments
This work was greatly inspired/informed by the work of Adam Constabaris, [for example here](https://github.com/NCSU-Libraries/bot-ip-scanner), and more generally the work of the Bot Blocking Brigade at NC State Libraries. 