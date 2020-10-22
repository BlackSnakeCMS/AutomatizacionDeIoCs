import requests
import socket
from urllib.parse import urlparse
from .models import DataModel, DataHash
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

otx_api = "d5387c798eed59f515bedd4a970f173d218c9d83c3d8efa0528006814afed073"
otx = OTXv2(otx_api)

class DataProcess:

    base_url = "https://signals.api.auth0.com/v2.0/ip/"
    api_token = 'db144477-3b91-47ca-892e-0641a78865d5'

    def __init__(self):
        super().__init__()
    
    def analyzeip(self, ip:str):
        url = self.base_url + ip
        res = requests.get(url, headers={'x-auth-token': self.api_token})
        payload = res.json()
        data = DataModel.fromDict(payload)
        return data

    def analyzeurl(self, url:str):
        domain = urlparse(url).netloc
        try:
            ip = socket.gethostbyname(domain)
            return self.analyzeip(ip)
        except:
            print(url)
            return None

    def analizehash(self, hash_value:str, hash_type:str):
        indicator = None
        if hash_type == 'md5':
            indicator = IndicatorTypes.FILE_HASH_MD5
        elif hash_type == 'sha1':
            indicator = IndicatorTypes.FILE_HASH_SHA1
        elif hash_type == 'sha256':
            indicator = IndicatorTypes.FILE_HASH_SHA256
        else:
            return 'invalid hash type'
        res = otx.get_indicator_details_by_section(indicator, hash_value, 'analysis')
        a = DataHash.fromDict(res, hash_type)
        if a == None:
            print(hash_value)
        return a
