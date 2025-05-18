import time
from zapv2 import ZAPv2

class ZAPScanner:
    def __init__(self):
        self.zap = ZAPv2(apikey="gki1bd0v1bbmsft2b8daqvfdqe", proxies={'http': 'http://localhost:8080'})

    def scan(self, url):
        try:
            print(f"Starting scan for {url}")
            self.zap.urlopen(url)

            # Spidering
            scan_id = self.zap.spider.scan(url)
            while int(self.zap.spider.status(scan_id)) < 100:
                time.sleep(1)

            # Active Scan
            scan_id = self.zap.ascan.scan(url)
            while int(self.zap.ascan.status(scan_id)) < 100:
                time.sleep(5)

            return [{
                'name': alert['alert'],
                'description': alert['description'],
                'risk': alert['risk']
            } for alert in self.zap.core.alerts()]

        except Exception as e:
            print(f"Scan failed: {str(e)}")
            return []
