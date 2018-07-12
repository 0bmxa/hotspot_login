from LoginStrategyType import LoginStrategyType
from Tools import Tools

# FIXME: Not cool, I guess
tools = Tools()

class DeutscheBahnICELoginStrategy(LoginStrategyType):
    host = "10.101.64.10"

    def name(self):
        return "Deutsche Bahn (ICE)"

    def login(self):
        # Get CSRF token and cookie
        print('1. Getting tokens')
        (_, head, body) = tools.send_HTTP_request('GET', self.host, '/de/', None, None)
        token = body.split('name="CSRFToken" value="')[1]
        token = token.split('"')[0]
        cookies = [value for (key, value) in head if key == 'Set-Cookie']
        cookie = cookies[0].split(';')[0]

        found_token  = ' Token ✔'  if (len(token) > 0) else ''
        found_cookie = ' Cookie ✔' if (len(cookie) > 0) else ''
        debugprint('Found:%s%s' % (found_token, found_cookie))

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Cookie': cookies[0],
        }

        # Form request body
        payload = {
            'login': 'true',
            'CSRFToken': token,
            'connect': '',
        }
        encoded_payload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        request_body = "&".join('{}={}'.format(key, value) for (key, value) in encoded_payload.items())

        print('2. Logging in')
        tools.send_HTTP_request('POST', self.host, '/de/', headers, request_body)

        print('3. Verifying')
        (_, _, body) = tools.send_HTTP_request('GET', self.host, '/de/', None, None)

        # Check if confirmation is in result
        if 'Sie sind jetzt online!' in body:
            print('Logged in.')
            return True
        return False


    def status(self):
        path = '/usage_info/'
        (_, _, result) = tools.send_HTTP_request('GET', self.host, path, None, None)

        percentage = result * 100
        print("Usage %f percent" % percentage)


    def logout(self):
        # Get CSRF token and cookie
        print('1. Getting tokens')
        (_, head, body) = tools.send_HTTP_request('GET', self.host, '/de/', None, None)
        token = body.split('name="CSRFToken" value="')[1]
        token = token.split('"')[0]
        cookies = [value for (key, value) in head if key == 'Set-Cookie']
        cookie = cookies[0].split(';')[0]

        found_token  = ' Token ✔'  if (len(token) > 0) else ''
        found_cookie = ' Cookie ✔' if (len(cookie) > 0) else ''
        debugprint('Found:%s%s' % (found_token, found_cookie))

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Cookie': cookies[0],
        }

        # Form request body
        payload = {
            'logout': 'true',
            'CSRFToken': token,
        }
        encoded_payload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        request_body = "&".join('{}={}'.format(key, value) for (key, value) in encoded_payload.items())

        print('2. Logging in')
        tools.send_HTTP_request('POST', self.host, '/de/', headers, request_body)

        print('3. Verifying')
        (_, _, body) = tools.send_HTTP_request('GET', self.host, '/de/', None, None)

        # Check if confirmation is in result
        if 'Sie sind jetzt online!' in body:
            print('Logged in.')
            return True
        return False
