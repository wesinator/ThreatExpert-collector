#!/usr/bin/env python3
from bs4 import BeautifulSoup
import os
from random import randint
import re
import requests
import sys
from time import sleep
from urllib.parse import quote_plus

reports_dir = "ThreatExpert reports"
te_md5s_list = "threatexpert_md5s.txt"

ie11_req_headers = {
    "Accept": "text/html, application/xhtml+xml, */*",
    "Accept-Language": "en-US",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive"
}

# Get MD5s on a report page
def get_report_md5s(reports_html):
    md5s = []
    soup = BeautifulSoup(reports_html, "lxml")

    for report in soup.find_all('a', href=True, target="_blank"):
        md5 = report["href"].replace("report.aspx?md5=", '')
        #print(md5)
        md5s.append(md5)

        # Save report file if not already saved
        report_filename = "%s/%s.html" % (reports_dir, md5)
        if not os.path.isfile(report_filename):
            # Sleep random seconds
            secs = randint(1, 4) # Could take up to 20*y*10 = 600 seconds for y = 3
            #print("Sleeping %d seconds" % secs)
            sleep(0.875*secs)

            get_te_report(md5)

    return md5s

# Download report for MD5
def get_te_report(md5):
    te_report_url = "http://www.threatexpert.com/report.aspx?md5=" + md5

    # Download the report URL
    report = requests.get(te_report_url, headers=ie11_req_headers).text

    # Save report page to html file
    print("Saving report for " + md5)
    with open("%s/%s.html" % (reports_dir, md5), 'w') as report_file:
        report_file.write(report)

    # Check for and download report screenshot
    get_te_screenshot(report, md5)

# Retrieve screenshot image from report if present
def get_te_screenshot(report_html, md5):
    img_re = "getimage\.aspx\?uid=[0-9a-fA-F-]{36}&image=screen&sub=[01]"
    parse_img = BeautifulSoup(report_html, "lxml")

    for img in parse_img.find_all("img", attrs = {"src": re.compile(img_re)}):
        img_path = img["src"]

        print("Getting image " + img_path)
        r = requests.get("http://www.threatexpert.com/" + img_path, headers=ie11_req_headers, stream=True)
        with open("%s/%s.gif" % (reports_dir, md5), 'wb') as img_file:
            img_file.write(r.raw.read())

def get_te_search_results(search_term):
    query = quote_plus(search_term)

    for i in range(1, 11):
        search_url = "http://www.threatexpert.com/reports.aspx?page=%d&find=%s" % (i, query)
        print("\nRetrieving results for '%s' page %d:" % (search_term, i))
        req = requests.get(search_url, headers=ie11_req_headers)

        get_report_md5s(req.text)

        # Stop if the search doesn't have any more result pages
        if "reports.aspx?page=%d&find=%s" % (i + 1, query) not in req.text:
            print("\nNo more results pages are available.")
            break

# Get MD5s and download reports for pages 1-10
def main():
    # Create reports dir if it doesn't already exist
    if not os.path.exists(reports_dir):
        os.mkdir(reports_dir)

    md5s = []

    md5_list = open(te_md5s_list, 'a+')
    existing_md5s = sorted(md5_list.readlines())

    # If no search terms, get all latest reports
    if len(sys.argv) == 1:
        # For pages 1-10 of reports, get MD5s
        for i in range(1, 11):
            te_reports_url = "http://www.threatexpert.com/reports.aspx?page=%d" % i
            req = requests.get(te_reports_url, headers=ie11_req_headers)
            md5s += get_report_md5s(req.text)

    # If search terms provided, retrieve results from search
    else:
        for term in sys.argv[1:]:
            search = term.strip('"')
            get_te_search_results(search)

    # Append new MD5s to MD5s list
    for md5 in md5s:
        if md5 not in existing_md5s:
            md5_list.write(md5 + '\n')

main()
