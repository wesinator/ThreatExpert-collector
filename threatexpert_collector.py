#!/usr/bin/env python
# Download latest TE report pages and screenshots if available. Ignores already downloaded reports.
from bs4 import BeautifulSoup
import httplib
import os
from random import randint
import re
import sys
from time import sleep
from urllib import quote_plus

md5_re = "report\.aspx\?md5=[0-9a-fA-F]{32}"
img_re = "getimage\.aspx\?uid=[0-9a-fA-F-]{36}&image=screen&sub=[01]"

req_headers = {
    "Accept": "text/html, application/xhtml+xml, */*",
    "Accept-Language": "en-US",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive"
}

reports_dir = "ThreatExpert reports/"

# Download a file over http given existing conn obj, header, url path, and output file path
def download(conn_obj, path, out_file):
    # Add slash to beginning of path if not already present
    if path[0] != '/':
        path = '/' + path

    try:
        conn_obj.request("GET", path, headers=req_headers)
        res = conn_obj.getresponse()

        if res.status == 200:
            data = res.read()
            with open(out_file, "wb") as f:
                f.write(data)
            return data

        else:
            print("Could not get %s\nStatus code: %d" % (path, res.status))

    except Exception as e:
        print("An error occurred downloading %s\n%s" % (path, str(e)))

# Parse a TE reports page using soup, download each report
def get_te_reports(reports_html, reports_dir):
    # Create reports dir if it doesn't already exist
    if not os.path.exists(reports_dir):
        os.mkdir(reports_dir)
    
    new_report_count = 0 # Counter for showing how many new reports are found
    parse = BeautifulSoup(reports_html, "lxml")

    for report in parse.find_all('a', attrs = {"href": re.compile(md5_re)}):
        report_path = report.get('href')
        md5 = report_path.replace("report.aspx?md5=", '')

        # If the report file for an md5 does not already exist, download the report
        if not os.path.isfile("%s/%s.html" % (reports_dir, md5)):
            # Sleep random seconds
            secs = randint(1, 4) # Could take up to 20*y*10 = 600 seconds for y = 3
            #print("Sleeping %d seconds" % secs)
            sleep(0.875*secs)
            
            # Append the public URL to the url file list:
            with open("report_urls.txt", "a") as url_list:
                url_list.write("http://www.threatexpert.com/%s\n" % report_path)

            new_report_count += 1 # Increment new report count
            print("Retrieving report for MD5: %s" % md5)
            report = download(conn, report_path, "%s/%s.html" % (reports_dir, md5))

            # If report has image, get the image
            if "The new window was created, as shown below:" in report:
                parse_img = BeautifulSoup(report, "lxml")
                for img in parse_img.find_all("img", attrs = {"src": re.compile(img_re)}):
                    img_path = img.get("src")

                    print("Downloading image for report " + md5)
                    img_data = download(conn, img_path, "%s/%s.gif" % (reports_dir, md5))

    print("%d new reports processed." % new_report_count)
    return new_report_count

def get_te_latest_reports():
    # Iterate over report pages 1 - 10
    for i in range(1, 11):
        # Build request for reports.aspx page
        print("\nRetrieving reports page %d\n" % i)
        conn.request("GET", "/reports.aspx?page=%d" % i, None, req_headers)
        res = conn.getresponse()

        # Call reports parser , show number of new reports processed.
        if res.status == 200:
            reports = res.read()
            count = get_te_reports(reports, reports_dir)

            # End the loop if no new reports are found
            if count == 0:
                print("Stopping since no new reports were found on the last page.")
                break
        else:
            print("Could not get reports page %d\nStatus code: %d" % (i, res.status))

def get_te_search_results(search_term):
    query = quote_plus(search_term)

    for i in range(1, 11):
        search_path = "/reports.aspx?page=%d&find=%s" % (i, query)
        print("\nRetrieving results for '%s' page %d:" % (search_term, i))
        conn.request("GET", search_path, None, req_headers)
        res = conn.getresponse()

        if res.status == 200:
            results = res.read()
            get_te_reports(results, reports_dir)

            # Stop if the search doesn't have any more result pages
            if "reports.aspx?page=%d&find=%s" % (i + 1, query) not in results:
                print("\nNo more results pages are available.")
                break

def main():
    # Init connection obj (doesn't actually connect yet)
    conn = httplib.HTTPConnection("www.threatexpert.com")

    # If no search query , go through the latest 10 report pages.
    if len(sys.argv) == 1:
        get_te_latest_reports()

    # If the user provided a search query , return the matching reports for the query and download them if they don't already exist.
    else:
        for term in sys.argv[1:]:
            search = term.strip('"')
            get_te_search_results(search)
    
    conn.close() # Close the TCP connection to TE when all pages are processed

main()
