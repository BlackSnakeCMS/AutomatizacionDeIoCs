import re
from data_process import DataProcess
import json

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
            "fake": 0
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

def analize(arg):
    global ips
    global hashes
    global urls
    global output
    ip = re.match(ip_pattern, arg)
    url = re.match(url_pattern, arg)
    resumen = output['resumen']
    if ip:
        resumen['ips']['cantidad'] += 1
        data = process.analyzeip(ip.group())
        if data.score >= 0:
            resumen['ips']['buenas'] += 1
        output['detalle']['ips'].append(
            data.toDict()
        )
    elif url:
        resumen['urls']['cantidad'] += 1
        data = process.analyzeurl(url.group())
        if data != None and data.score >= 0:
            resumen['urls']['buenas'] += 1
        if data == None:
            resumen['urls']['fake'] += 1
        else:
            output['detalle']['urls'].append(
                data.toDict()
            )
    else:
        resumen['hashes']['cantidad'] += 1
    

with f as csv_file:
    count = 0
    for row in csv_file:
        row = row.strip()
        if row != '':
            analize(row)
            count += 1
        if count == 150:
            break
    print(count)

print(output)

with open('output.json', 'w', encoding='utf-8') as out:
    json.dump(output, out)