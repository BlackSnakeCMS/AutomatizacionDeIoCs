from src.data_process import DataProcess
import json
import iocextract as ioc
import sys, getopt

def analize(content):
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
                "no_antivirus": 0
            }
        },
        "detalle":{
            "urls": [],
            "ips": [],
            "hashes": []
        }
    }
    process = DataProcess()
    resumen = output['resumen']
    ips = ioc.extract_ips(content, refang=True)
    urls = ioc.extract_urls(content, refang=True)
    md5s = ioc.extract_md5_hashes(content)
    sha1s = ioc.extract_sha1_hashes(content)
    sha256s = ioc.extract_sha256_hashes(content)
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
    for md5 in md5s:
        resumen['hashes']['cantidad'] += 1
        datahas = process.analizehash(md5, 'md5')
        if datahas != None:
            if datahas.count_antivirus_detected() == 0:
                resumen['hashes']['no_antivirus'] += 1
            output['detalle']['hashes'].append(
                datahas.toDict()
            )
        else:
            output['detalle']['hashes'].append(
                {'hash': md5, 'type': 'md5'}
            )
    for sha1 in sha1s:
        resumen['hashes']['cantidad'] += 1
        datahas = process.analizehash(sha1, 'sha1')
        if datahas != None: 
            if datahas.count_antivirus_detected() == 0:
                resumen['hashes']['no_antivirus'] += 1
            output['detalle']['hashes'].append(
                datahas.toDict()
            )
        else:
            output['detalle']['hashes'].append(
                {'hash': sha1, 'type': 'sha1'}
            )
    for sha256 in sha256s:
        resumen['hashes']['cantidad'] += 1
        datahas = process.analizehash(sha256, 'sha256')
        if datahas != None:
            if datahas.count_antivirus_detected() == 0:
                resumen['hashes']['no_antivirus'] += 1
            output['detalle']['hashes'].append(
                datahas.toDict()
            )
        else:
            output['detalle']['hashes'].append(
                {'hash': sha256, 'type': 'sha256'}
            )
    return output


def main(argv):
    content = ""
    output = {}
    inputfile = 'data.csv'
    outputfile = 'output.json'
    try:
        opts, args = getopt.getopt(argv, 'hi:o:', ['ifile=', 'ofile='])
    except getopt.GetoptError:
        print('main.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        print(arg)
        if opt == '-h':
            print('usage: main.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
            

    f = open(inputfile, 'r', encoding='utf-8')
    print("Comenzando analisis...")
    with f as csv_file:
        count = 0
        for row in csv_file:
            row = row.strip()
            content += row + '\n'
        output = analize(content)
    print("Fin del análisis")

    with open(outputfile, 'w', encoding='utf-8') as out:
        json.dump(output, out)

if __name__ == "__main__":
    main(sys.argv[1:])