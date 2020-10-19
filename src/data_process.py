import requests
import socket
from models import DataModel

class DataProcess:

    base_url = "https://signals.api.auth0.com/v2.0/ip/"
    api_token = 'db144477-3b91-47ca-892e-0641a78865d5'
    
    def __init__(self):
        super().__init__()
    
    def analyzeip(self, ip:str):
        url = self.base_url + ip.replace('[.]', '.')
        res = requests.get(url, headers={'x-auth-token': self.api_token})
        payload = res.json()
        data = DataModel.fromDict(payload)
        return data

    def analyzeurl(self, url:str):
        url = url.replace('[.]', '.')
        try:
            ip = socket.gethostbyname(url)
            return self.analyzeip(ip)
        except:
            print(url)
            return None
