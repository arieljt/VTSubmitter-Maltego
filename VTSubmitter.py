#Maltego Transfrom - VirusTotal submitter information @arieljt

from MaltegoTransform import *
import requests
import json

apiurl = "https://www.virustotal.com/api/v3/"
apikey = "API_KEY"


mt = MaltegoTransform()
mt.parseArguments(sys.argv)
file_hash = mt.getVar('properties.hash').strip()


try:
    headers = {'x-apikey': apikey}
    response = requests.get(apiurl + 'files/' + file_hash + '/submissions', headers=headers) 
    response_json = response.json()

    if 'attributes' in response_json['data'][0]:
        for item in response_json['data']:
            me = mt.addEntity("maltego.VTSubmitter", '%s' % item['attributes']['source_key'].encode("ascii"))
            if 'country' in item['attributes']:
            	me.addAdditionalFields("VTSubmitter.Country","Submitter Country",True,'%s' % item['attributes']['country'].encode("ascii"))
            if 'interface' in item['attributes']:
            	me.addAdditionalFields("VTSubmitter.Interface","Submitter Interface",True,'%s' % item['attributes']['interface'].encode("ascii"))
            me.setLinkLabel("VT Submitter")

except:
    mt.addUIMessage("Exception Occurred")

    
mt.returnOutput()

