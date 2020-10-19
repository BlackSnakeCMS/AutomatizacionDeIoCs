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

