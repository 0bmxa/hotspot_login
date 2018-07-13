import urllib

from LoginStrategyType import LoginStrategyType
from Tools import *



# FIXME: Not cool, I guess
tools = Tools()

class MeinHotspotLoginStrategy(LoginStrategyType):
    host = "login.meinhotspot.com"

    def name(self):
        return "MeinHotspot"

    def login(self):
        mac_address = tools.get_MAC_address()
        payload = {
            'username': mac_address,
            'password': mac_address,
            'mac': mac_address
        }

        headers = {'content-type': "application/x-www-form-urlencoded"}

        # Form request body
        encoded_payload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        request_body = "&".join('{}={}'.format(key, value) for (key, value) in encoded_payload.items())

        path = "/login"
        method = "POST"
        (_, _, result) = tools.send_HTTPS_request(method, self.host, path, headers, request_body)

        # If req failed, show response and stop here
        if 'Sie wurden soeben auf dem Hotspot eingeloggt' in result:
            print('Logged in.')
            return True

        error_messages = [
            'Your maximum daily usage time has been reached',
            'RADIUS server is not responding'
        ]
        for message in error_messages:
            if message in result:
                print(message)
                return False

        debugprint(result)
        return False


    def status(self):
        headers = {'content-type': "application/x-www-form-urlencoded"}

        path = "/mhstatus.html"
        method = "GET"
        (_, _, result) = tools.send_HTTPS_request(method, self.host, path, headers, None)

        if not '<table' in result:
            print("ERROR: Malformed status page")
            return

        tools.print_HTML_table(result)
