import re
from data_process import DataProcess
import json
import iocextract as ioc

ips = 0
hashes = 0
urls = 0

ip_pattern = r"^\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}$"
url_pattern = r'^[\w-]+(\[\.\][\w-]+){1,3}$'


process = DataProcess()

output = {
    "resumen":{
        "urls": {
            "cantidad": 0,
            "buenas": 0,
        },
        "ips": {
            "cantidad": 0,
            "buenas": 0
        },
        "hashes": {
            "cantidad": 0,
            "antivirus": 0
        }
    },
    "detalle":{
        "urls": [],
        "ips": [],
        "hashes": []
    }
}

f = open('data.csv', 'r', encoding='utf-8')

def analize():
    global ips
    global hashes
    global urls
    global output
    global content
    resumen = output['resumen']
    ips = ioc.extract_ips(content, refang=True)
    urls = ioc.extract_urls(content, refang=True)
    hashes = ioc.extract_hashes(content)
    for ip in ips:
        resumen['ips']['cantidad'] += 1
        data = process.analyzeip(ip)
        if data.score >= 0:
            resumen['ips']['buenas'] += 1
        output['detalle']['ips'].append(
            data.toDict()
        )
    for url in urls:
        resumen['urls']['cantidad'] += 1
        data = process.analyzeurl(url)
        if data != None: 
            if data.score >= 0:
                resumen['urls']['buenas'] += 1    
            output['detalle']['urls'].append(
                data.toDict()
            )
    for hash in hashes:
        resumen['hashes']['cantidad'] += 1
    
content = ''

with f as csv_file:
    count = 0
    for row in csv_file:
        row = row.strip()
        content += row + '\n'
    analize()
        
print(output)

with open('output.json', 'w', encoding='utf-8') as out:
    json.dump(output, out)