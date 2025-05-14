`get-bots.py` is a script that processes the output of Apache logs (Combined format) to identify bots based on ASN ranges from ASN data downloaded from [IPinfo.io](https://ipinfo.io/account/data-downloads). 


## Usage

```
python get-bots.py accessfile [-r] [-o output-format]
```
- accessfile: path to your access log
- r: process a rails log (log level must be set to debug)
- o: this option allows you to dump entire data output into a csv file or json file (specify json or csv as the output-format). 

Basic example:
```
python get-bots.py my-app-secure_access.log 
```
Example of processing a rails log and sending the output to a csv file:
```
python get-bots.py production.log -r -o csv
```
## Output data

The `get-bots.py` script defaults to outputting the top ten "bot swarms" in json format. By specifying '-o csv' or '-o json' the script will output all IP ranges found into a csv or json file. Example of data collected:
```
{
        "asn_ip_range": "51.222.0.0-51.222.255.255",
        "ip_count": 20,
        "total_requests": 317,
        "time_range_seconds": 457470.0,
        "asn": "AS16276",
        "asn_name": "OVH SAS",
        "asn_domain": "ovhcloud.com",
        "lowest_ip_found": "51.222.253.1",
        "highest_ip_found": "51.222.253.20",
        "cidr_range": "51.222.253.0/27",
        "total_cidr_ips": 32,
        "requests_per_ip": 15.85,
        "std_dev_requests": 5.01,
        "variation_coefficient": 31.61,
        "worst_offender": "51.222.253.3",
        "worst_offender_user_agent": [
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
        ],
        "worst_offenders_request_total": 28,
        "worst_offender_common_request": "/collections/?f[topic_facet][]=X&page=X&to=X",
        "worst_offender_common_request_count": 2,
        "first_hit": "2025-03-02 04:16:38 -0500",
        "last_hit": "2025-03-07 11:21:08 -0500"
    }
```

## requirements/venv setup
Download fresh IP to ASN data (as `asn.csv`) from [IPinfo.io](https://ipinfo.io/account/) and place in the `data` directory. 

Basic virtual environment install:
```
# install python virtual environment
python -m venv venv
# activate virtual environment
source venv/bin/activate
# install dependencies
pip install -r requirements.txt
```
## warnings
This code has not been fully tested or vetted, especially the rails output option.  

## acknowledgments
This work was greatly inspired/informed by the work of Adam Constabaris, [for example here](https://github.com/NCSU-Libraries/bot-ip-scanner), and more generally the work of the Bot Blocking Brigade at NC State Libraries. 