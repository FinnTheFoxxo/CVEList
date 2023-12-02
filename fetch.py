from datetime import datetime
import requests
import glob
import os

x = glob.glob(os.path.join("cve", '*'))
for y in x:
    os.remove(y)

def Fetch():
    lst = requests.get("https://www.tenable.com/cve/api/v1?sort=newest")
    sorting = []
    ref = []
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
                ref_list = cve_url.json()['data']['_source']['references']
                for url in ref_list:
                    ref.append(url['url'])
            except (KeyError, IndexError):
                ref = None
            score = cve_url.json()['data']['_source']['cvss3_severity']
            desc = cve_url.json()['data']['_source']['description']
        if len(ref) == 0:
            refs = "N/A"
        else:
            refs = ''.join(ref); refs = refs.replace('http', ' http')
        if score == "Critical":
            print(f"CVE-{datetime.now().year}-{y} - \033[0;91m{score} ({base_score})\033[0;0m \n {desc} \n References: {refs} \n")
        elif score == "High":
            print(f"CVE-{datetime.now().year}-{y} - \033[38;5;202m{score} ({base_score})\033[0;0m \n {desc} \n References: {refs} \n")
        elif score == "Medium":
            print(f"CVE-{datetime.now().year}-{y} - \033[0;93m{score} ({base_score})\033[0;0m \n {desc} \n References: {refs} \n")
        elif score == "Low":
            print(f"CVE-{datetime.now().year}-{y} - \033[38;5;82m{score} ({base_score})\033[0;0m \n {desc} \n References: {refs} \n")
        io.write(f"CVE-{datetime.now().year}-{y} - {score} ({base_score}) \n {desc} \n References: {refs} \n\n")
        io.flush(); ref.clear()

Fetch()

