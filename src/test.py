from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import json

otx = OTXv2("d5387c798eed59f515bedd4a970f173d218c9d83c3d8efa0528006814afed073")

#a = otx.submitted_files(hashes=['5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823'])
a = otx.get_indicator_details_by_section(IndicatorTypes.FILE_HASH_MD5, '16cda323189d8eba4248c0a2f5ad0d8f', 'analysis')

#a = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5 , "15a4eb525072642bb43f3c188a7c3504")


with open('test4.json', 'w', encoding='utf-8') as out:
    json.dump(a, out)
