﻿## SubSniper
SubSniper is a  subdomain enumeration tool written in Python. It uses search engine queries and DNS resolution to discover valid subdomains for a given target domain. The tool supports saving results in various formats such as JSON, CSV, or plain text.

## Features
Multithreaded Subdomain Enumeration: Quickly gathers potential subdomains using multiple search engines.
DNS Validation: Ensures discovered subdomains are valid by performing DNS resolution.
Customizable Output Formats: Save results in JSON, CSV, or TXT format.
Extendable: Easily add more search engines or APIs for improved subdomain discovery.

## Installation
Ensure you have Python 3.x and the required dependencies installed:

```bash
pip install requests beautifulsoup4 dnspython
```

## Usage
Run the script from the command line with the following options:

```python 
python SubSniper.py <domain> [-o <output_file>] [--format <format>] 
```

Command-Line Arguments
- domain (required): The target domain to enumerate subdomains.
- -o, --output (optional): Save the discovered subdomains to a file.
- --format (optional): Specify the output format (json, csv, or txt). Defaults to txt.

## Examples
1 Basic Subdomain Enumeration:

```python 
python SubSniper.py example.com
```

2 Save Output as JSON:

```python
python SubSniper.py example.com -o results.json --format json
```
3 Save Output as CSV:

```python 
python SubSniper.py example.com -o results.csv --format csv
```

4 Save Output as TXT:

```python 
python SubSniper.py example.com -o results.txt --format txt
```
## Logging
SubSniper provides detailed logging of its operations, including query actions, DNS validation, and any errors encountered during the process.
