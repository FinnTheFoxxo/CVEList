from datetime import datetime
import requests
import json
import time
import glob
import os

x = glob.glob(os.path.join("cve", '*'))
for y in x:
    os.remove(y)

def Fetch():
    lst = requests.get("https://www.tenable.com/cve/api/v1?sort=newest")
    sorting = []
    for x in range(1, 49):
        cve = sorting.append(lst.json()['data']['hits'][x]['_id'][9:])
    sorting = list(map(int, sorting))
    sorting = sorted(sorting, reverse=True)
    first = sorting[0]
    io = open(f'cve/CVE-{datetime.now().year}-{first}', "w")
    for y in sorting:
        cve_url = requests.get(f"https://www.tenable.com/cve/api/v1/CVE-{datetime.now().year}-{y}")
        if cve_url.status_code != 200:
            sorting.remove(y)
        else:
            try:
                base_score = cve_url.json()['data']['_source']['cvss3_base_score']
            except KeyError:
                base_score = "N/A"
            try:
                ref = cve_url.json()['data']['_source']['references'][0]['url']
            except KeyError:
                ref = "N/A"
            except IndexError:
                ref = "N/A"
            score = cve_url.json()['data']['_source']['cvss3_severity']
            desc = cve_url.json()['data']['_source']['description']
        print(f"CVE-{datetime.now().year}-{y} - {score} ({base_score}) \n {desc} \n References: {ref} \n")
        io.write(f"CVE-{datetime.now().year}-{y} - {score} ({base_score}) \n {desc} \n References: {ref} \n\n")
        io.flush()

Fetch()

