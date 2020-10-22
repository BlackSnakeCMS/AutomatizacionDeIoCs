class DataModel:
    url:str
    ip:str
    country:str
    score:int

    def __init__(self, url, ip, country, score):
        self.url = url
        self.ip = ip
        self.country = country
        self.score = score

    @staticmethod
    def fromDict(data:dict):
        fullip = data['fullip']
        return DataModel(
            url=fullip['hostname'],
            ip=fullip['geo'].get('address'),
            country=fullip['geo']['country_names']['es'],
            score=fullip['baddomain'].get('score')
        )
    
    def toDict(self):
        return {
            'ip': self.ip,
            'url': self.url,
            'country': self.country,
            'score': self.score,
            'reputation': self.reputation()
        }

    def reputation(self):
        if self.score != None:
            if self.score >= 0:
                return 'Sin riesgo'
            elif self.score == -1:
                return 'Riesgo bajo'
            elif self.score == -2:
                return 'Riesgo medio'
            elif self.score == -3:
                return 'Alto riesgo'
            else:
                return 'No especificado'
        else:
            return 'Sin score'
    
    def __str__(self):
        return str(self.toDict())



def __get_data_antivirus__(data):
    return {
        'avast': __get_value__(data, 'avast'),
        'clamav': __get_value__(data, 'clamav'),
        'avg': __get_value__(data, 'avg')
    }

def __get_value__(data, key):
    value = data.get(key, 'unknown')
    if value != 'unknown':
        return len(value.get('results', []).keys()) > 0
    return value

def __get_data_cuckoo__(data):
    out = {
        'McAfee': 'unknown',
        'ESET-NOD32': 'unknown',
        'F-Secure': 'unknown',
        'Kaspersky': 'unknown'
    }
    if data != None:
        vtotal = data['result'].get('virustotal')
        if vtotal != None:
            scans = vtotal.get('scans')
            out['McAfee'] = scans.get('McAfee', {'detected': 'unknown'})['detected']
            out['ESET-NOD32'] = scans.get('ESET-NOD32', {'detected': 'unknown'})['detected']
            out['F-Secure'] = scans.get('F-Secure', {'detected': 'unknown'})['detected']
            out['Kaspersky'] = scans.get('Kaspersky', {'detected': 'unknown'})['detected']
    return out


class DataHash:
    sha1:str
    sha256:str
    md5:str
    antivirus:dict
    hashtype:str

    def __init__(self, sha1, sha256, md5, antivirus, hashtype):
        self.sha1 = sha1
        self.sha256 = sha256
        self.md5 = md5
        self.antivirus = antivirus
        self.hashtype = hashtype

    def  toDict(self):
        return {
            'hash': self.__get_hash__(),
            'type': self.hashtype,
            'detected': self.antivirus
        }
    
    def __get_hash__(self):
        if self.hashtype == 'md5':
            return self.md5
        elif self.hashtype == 'sha1':
            return self.sha1
        elif self.hashtype == 'sha256':
            return self.sha256
        else:
            return 'unsoport hash type: ' + self.hashtype
    
    def count_antivirus_detected(self):
        values = list(self.antivirus.values())
        return len(values) - values.count(False) - values.count('unknown')

    @staticmethod
    def fromDict(data, hashtype):
        analysis = data.get('analysis')
        if analysis != None:
            dataHash = DataHash(
                sha1=analysis['info']['results']['sha1'],
                sha256=analysis['info']['results']['sha256'],
                md5=analysis['info']['results']['md5'],
                antivirus=__get_data_antivirus__(analysis['plugins']),
                hashtype=hashtype
            )
            cuckoo = analysis['plugins'].get('cuckoo')
            dataHash.antivirus.update(__get_data_cuckoo__(cuckoo))
            return dataHash
        return None

    def __str__(self):
        return self.toDict().__str__()