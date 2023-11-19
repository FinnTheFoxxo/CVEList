from datetime import datetime
import requests
import json
import time
import glob
import os

x = glob.glob(os.path.join("cve", '*'))
for y in x:
    os.remove(y)

def Fetch(url):
    lst = requests.get(url)
    sorting = []
    for x in range(1, 49):
        cve = sorting.append(lst.json()['pageProps']['cves'][x]['_id'][9:])
    sorting = list(map(int, sorting))
    sorting = sorted(sorting, reverse=True)
    first = sorting[0]
    io = open(f'cve/CVE-{datetime.now().year}-{first}', "w")
    for y in sorting:
        cve_url = requests.get(f"https://www.tenable.com/_next/data/MpvWdm2FI6kN9_9sRNrR_/en/cve/CVE-{datetime.now().year}-{y}.json?id=CVE-{datetime.now().year}-{y}")
        if cve_url.status_code != 200:
            sorting.remove(y)
        else:
            try:
                base_score = cve_url.json()['pageProps']['cve']['cvss3_base_score']
            except KeyError:
                base_score = "N/A"
            try: 
                ref = cve_url.json()['pageProps']['cve']['references'][0]['url']
            except KeyError:
                ref = "N/A"
            except IndexError:
                ref = "N/A"
            score = cve_url.json()['pageProps']['cve']['cvss3_severity']
            desc = cve_url.json()['pageProps']['cve']['description']
        print(f"CVE-{datetime.now().year}-{y} - {score} ({base_score}) \n {desc} \n References: {ref} \n")
        io.write(f"CVE-{datetime.now().year}-{y} - {score} ({base_score}) \n {desc} \n References: {ref} \n\n")
        io.flush()


Fetch("https://www.tenable.com/_next/data/MpvWdm2FI6kN9_9sRNrR_/en/cve/newest.json")