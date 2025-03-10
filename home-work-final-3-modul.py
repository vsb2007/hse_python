import hashlib
import json
import os
import requests
from zipfile import ZipFile
import hashlib
import vulners

import env

print("Task 1:")

TOKEN = env.VIRUS_TOTAL_API_KEY
api_url = "https://www.virustotal.com/api/v3/files"
headers = {"x-apikey": str(TOKEN)}

zip_file = 'protected_archive.zip'
password = 'netology'

extract_path = "dz_final"

with ZipFile(zip_file) as zf:
  zf.extractall(pwd=bytes(password,'utf-8'),path=extract_path)
def get_sha256(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


for filename in os.listdir(extract_path):
    file_sha256 = get_sha256(extract_path + "/" + filename)
    file_md5 = get_md5(extract_path + "/" + filename)
    # print(file_sha256)
    # print(file_md5)
    with open(extract_path + "/" + filename, "rb") as file:
        files = {"file": (extract_path + "/" + filename, file)}
        response_text = requests.post(api_url, headers=headers, files=files).json()
        # print(response_text)

        request_url = response_text["data"]["links"]["self"]
        resp = requests.get(request_url, headers=headers).json()
        results = resp['data']['attributes']['results']
        max_width = 15
        print("stage 4.1:")
        for av_name, av_result in results.items():
            if av_result['result'] is not None:
                print(f"{av_name.ljust(max_width)}: Detected")
            else:
                # print(f"{av_name.ljust(max_width)}: Not Detected")
                continue

        print("stage 4.2:")
        avs = ['Fortinet', 'McAfee', 'Yandex', 'Sophos']
        for av in avs:
            if av in resp['data']['attributes']['results']:
                print(f"{av.ljust(max_width)}: {resp['data']['attributes']['results'][av]['result']}")
            else:
                print(f"{av.ljust(max_width)}: Not found")

    # Behavior - отсутствует - потому дальше закоментировал и рассматривал, по выводу тоже не нашел ничего похожего на список ip и доменов
    # response_sha256 = requests.get(api_url + "/" + str(file_sha256), headers=headers)
    # print(response_sha256.json())
    # response_md5 = requests.get(api_url + "/" + str(file_md5), headers=headers)
    # print(response_md5.json())

print("Task 2:")
#
softwares = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version":
        "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version":
        "2.4.29"},
    {"Program": "DjVu Reader", "Version":
        "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version":
        "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version":
        "61.0.1"}
]

VULNER_TOKEN = env.VULNERS_API_KEY
vulners_api = vulners.Vulners(api_key=str(VULNER_TOKEN))
# search_result = vulners_api.search("type:cve AND enchantments.exploitation.wildExploited:*")
for software in softwares:
    search_apps = [
        {
            "product": software['Program'],
            "version": software['Version']
        }
    ]
    search_result = vulners_api.audit_software(software=search_apps)
    print(f"product: {software['Program']}, Version: {software['Version']}")
    for vuln in search_result[0]['vulnerabilities']:
        if vuln['type'] == 'cve':
            print(f"\t{vuln['id']}")
            cve_exploits = vulners_api.find_exploit_all(vuln['id'], limit=5)
            if len(cve_exploits) != 0:
                print("\t\tЕсть информация об эксплойтах")
    # break

