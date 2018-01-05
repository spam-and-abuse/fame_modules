import hashlib
import requests
from fame.core.module import ProcessingModule


class VirusTotalPub(ProcessingModule):
    name = "virustotal_pub"
    description = "Check hash against VT database"
    config = [
        {
            'name': 'VT_API_KEY',
            'type': 'str',
            'description': 'Virustotal API key'
        },
    ]
   
    def each(self, target):
        vt_api_url = 'http://www.virustotal.com/vtapi/v2/{method!s}/report'
        params = {'apikey': self.VT_API_KEY,
                  'resource': None }
        method = 'file'
        
        self.results = {
            'VT': u'',
            'Detections': u'',
            'Raw': u''
        }
        
        # calulate target hash 
        h = hashlib.sha256()
        with open(target, 'rb') as f:
            h.update(f.read())
        params['resource'] = h.hexdigest()
 
        r = requests.get(url=vt_api_url.format(method=method), params=params)
        if r.status_code == 200:
            self.log('debug', 'VirusTotal message: {}'.format(r.json()['verbose_msg']))
           
            if r.json()['response_code'] == 1:
                self.results['Detections'] = u'{}/{}'.format(r.json()['positives'], r.json()['total'])
                self.results['VT'] = r.json()['permalink']
            self.results['Raw'] = r.json()
 
        elif r.status_code == 204:
            self.log('warning', 'VirusTotal public API request rate limit exceeded. Try again later.')
        elif r.status_code == 403:
            self.log('error', 'You have tried to perform calls to VirusTotal\'s functions for which you do not have the required privileges.')

        return True

