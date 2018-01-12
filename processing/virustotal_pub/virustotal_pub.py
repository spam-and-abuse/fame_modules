import hashlib
import requests
from fame.core.module import ProcessingModule


class VirusTotalPub(ProcessingModule):
    name = "virustotal_pub"
    description = "Check file hash or url against VirusTotal database"
    config = [
        {
            'name': 'VT_API_KEY',
            'type': 'str',
            'description': 'Virustotal API key'
        },
    ]

    def each_with_type(self, target, obj_type):
        vt_api_url = 'http://www.virustotal.com/vtapi/v2/{method!s}/report'
        params = {'apikey': self.VT_API_KEY,
                  'resource': None}

        self.results = {
            'VT': u'',
            'Detections': u'',
            'Raw': u''
        }

        if obj_type == 'url':
            method = 'url'
            params['resource'] = target
        elif obj_type == 'hash':
            return True
        else:
            method = 'file'
            # try to calulate target hash (assuming it is a file)
            h = hashlib.sha256()
            try:
                with open(target, 'rb') as f:
                    h.update(f.read())
                params['resource'] = h.hexdigest()
            except IOError: 
                self.log('debug', 'No such file: {}'.format(target))
                return False

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
