#!/usr/bin/env python3

import http.client
import urllib
import datetime
import subprocess
from colorama import Fore
import re

class LoginStrategyType(object):
    def name(self): raise NotImplementedError()
    def checkPreconditions(self): return (True, None) # (success, message)
    def login(self): raise NotImplementedError()
    def status(self): raise NotImplementedError()
    def logout(self): raise NotImplementedError()

class MeinHotspotLoginStrategy(LoginStrategyType):
    host = "login.meinhotspot.com"

    def name(self):
        return "MeinHotspot"

    def login(self):
        macAddress = tools.getMACAddress()
        payload = {
            'username': macAddress,
            'password': macAddress,
            'mac': macAddress
        }

        headers = {'content-type': "application/x-www-form-urlencoded"}

        # Form request body
        encodedPayload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        requestBody = "&".join('{}={}'.format(key, value) for (key, value) in encodedPayload.items())

        path = "/login"
        method = "POST"
        (_, _, result) = tools.sendHTTPSRequest(method, self.host, path, headers, requestBody)

        # If req failed, show response and stop here
        if 'Sie wurden soeben auf dem Hotspot eingeloggt' in result:
            print('Logged in.')
            return True

        errorMessages = [
            'Your maximum daily usage time has been reached',
            'RADIUS server is not responding'
        ]
        for message in errorMessages:
            if message in result:
                print(message)
                return False

        print(result)
        return False


    def status(self):
        headers = {'content-type': "application/x-www-form-urlencoded"}

        path = "/mhstatus.html"
        method = "GET"
        (_, _, result) = tools.sendHTTPSRequest(method, self.host, path, headers, None)

        if not '<table' in result:
            print("ERROR: Malformed status page")
            return

        tools.printHTMLTable(result)


class BooksAndBagelsLoginStrategy(MeinHotspotLoginStrategy):
    def name(self):
        return "BooksAndBagels"

    def checkPreconditions(self):
        # Fine Bagels Hotspot on weekends:
        # Saturday only from 17:00, Sunday from 19:00 on
        now = datetime.datetime.now()
        if (now.weekday() == 5 and now.hour < 17) or \
           (now.weekday() == 6 and now.hour < 19):
            return (False, 'The hotspot is offline.')
        return (True, None)

class DeutscheBahnICELoginStrategy(LoginStrategyType):
    host = "10.101.64.10"

    def name(self):
        return "Deutsche Bahn (ICE)"

    def login(self):
        # Get CSRF token and cookie
        print('1. Getting tokens')
        (_, head, body) = tools.sendHTTPRequest('GET', self.host, '/de/', None, None)
        token = body.split('name="CSRFToken" value="')[1]
        token = token.split('"')[0]
        cookies = [value for (key, value) in head if key == 'Set-Cookie']
        cookie = cookies[0].split(';')[0]

        foundToken  = ' Token ✔'  if (len(token) > 0) else ''
        foundCookie = ' Cookie ✔' if (len(cookie) > 0) else ''
        print('Found:%s%s' % (foundToken, foundCookie))

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
        encodedPayload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        requestBody = "&".join('{}={}'.format(key, value) for (key, value) in encodedPayload.items())

        print('2. Logging in')
        tools.sendHTTPRequest('POST', self.host, '/de/', headers, requestBody)

        print('3. Verifying')
        (_, _, body) = tools.sendHTTPRequest('GET', self.host, '/de/', None, None)

        # Check if confirmation is in result
        if 'Sie sind jetzt online!' in body:
            print('Logged in.')
            return True
        return False


    def status(self):
        path = '/usage_info/'
        (_, _, result) = tools.sendHTTPRequest('GET', self.host, path, None, None)

        percentage = result * 100
        print("Usage %f percent" % percentage)


    def logout(self):
        # Get CSRF token and cookie
        print('1. Getting tokens')
        (_, head, body) = tools.sendHTTPRequest('GET', self.host, '/de/', None, None)
        token = body.split('name="CSRFToken" value="')[1]
        token = token.split('"')[0]
        cookies = [value for (key, value) in head if key == 'Set-Cookie']
        cookie = cookies[0].split(';')[0]

        foundToken  = ' Token ✔'  if (len(token) > 0) else ''
        foundCookie = ' Cookie ✔' if (len(cookie) > 0) else ''
        print('Found:%s%s' % (foundToken, foundCookie))

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Cookie': cookies[0],
        }

        # Form request body
        payload = {
            'logout': 'true',
            'CSRFToken': token,
        }
        encodedPayload = dict([(urllib.parse.quote_plus(key), urllib.parse.quote_plus(value)) for (key, value) in payload.items()])
        requestBody = "&".join('{}={}'.format(key, value) for (key, value) in encodedPayload.items())

        print('2. Logging in')
        tools.sendHTTPRequest('POST', self.host, '/de/', headers, requestBody)

        print('3. Verifying')
        (_, _, body) = tools.sendHTTPRequest('GET', self.host, '/de/', None, None)

        # Check if confirmation is in result
        if 'Sie sind jetzt online!' in body:
            print('Logged in.')
            return True
        return False


class DefaultLoginStrategy(LoginStrategyType):
    def name(self):
        return "Default"

    def login(self):
        # Find captive portal URL
        print("1. Looking for a captive portal")

        headers = { 'host': 'neverssl.com' }
        hostIP = '13.32.158.44'
        (status, head, body) = tools.sendHTTPRequest('GET', hostIP, '/', headers, None)
        location = [field[1] for field in head if field[0] == 'Location']
        if len(location) < 1:
            print("No captive portal found.")
            return True

        # Found a captive portal
        captivePortalURL = location[0]
        print("Found captive portal at:", captivePortalURL)

        captive_portal_IP = None

        # Replace (potential) domain name with IP, because I'm using my own DNS
        print('2. Replacing domain name with IP')

        url_parts = urllib.parse.urlparse(captive_portal_URL)
        captive_portal_hostname = url_parts.netloc

        # Check if hostname is an IP already, if not, resolve
        if re.search('[^0-9\.]', captive_portal_hostname):
            # Get default gateway
            default_gateway = tools.getGateway()

            # Get portal IP
            captive_portal_IP = tools.getIPForDomain(captive_portal_hostname, default_gateway)
            print("Replaced %s with %s" % (captive_portal_hostname, captive_portal_IP))

        else:
            print("%s is already an IP" % captive_portal_IP)
            captive_portal_IP = captive_portal_hostname
        
        # Get the captive portal HTML
        secure = False #(url_parts.scheme == 'https')
        path = url_parts.geturl().split(captive_portal_hostname)[1]
        headers = { 'host': captive_portal_hostname }
        (_, _, body) = tools.sendHTTPRequest('GET', captive_portal_IP, path, headers, None, secure)
        

        # Print it fancy
        line = '=' * 80
        print('%s%s\nSTART CAPTIVE PORTAL HTML\n%s%s' % (Fore.RED, line, line, Fore.RESET))

        # Find & highlight a form
        form_start = re.search('<\s*form[^>]*>', body)
        if form_start:
            (form_start_index, _) = form_start.span(0)

            form_end = re.search('</\s*form\s*>', body)
            (_, form_end_index) = form_end.span(0)
            
            before_form = body[:form_start_index]
            form = body[form_start_index:form_end_index]
            after_form = body[form_end_index:]
            print('%s%s%s%s%s' % (before_form, Fore.CYAN, form, Fore.RESET, after_form))

        else:
            print(body)
        
        print('%s%s\nEND CAPTIVE PORTAL HTML\n%s%s' % (Fore.RED, line, line, Fore.RESET))


    def status(self):
        print('Unknown.')


class HotspotLogin(object):
    def main(self):

        tools.getMACAddress()

        # Get SSID
        print('%s[SSID]%s' % (Fore.YELLOW, Fore.RESET))
        ssid = tools.getSSID()
        if not ssid:
            print('Not connected to WiFi')
            return
        print(ssid)

        # Get login strategy
        print('\n%s[Strategy]%s' % (Fore.YELLOW, Fore.RESET))
        strategyClass = self.strategyForSSID(ssid)
        strategy = strategyClass()
        print("%s strategy" % strategy.name())

        # Check Preconditions
        (preconditionsSuccess, preconditionsMessage) = strategy.checkPreconditions()
        if preconditionsMessage:
            print('\n%s[Preconditions]%s' % (Fore.YELLOW, Fore.RESET))
            print(preconditionsMessage)
        if not preconditionsSuccess:
            return

        # Login
        print('\n%s[Login]%s' % (Fore.YELLOW, Fore.RESET))
        loginSuccess = strategy.login()
        if not loginSuccess:
            print('Login was not successful.')
            return

        # Status
        print('\n%s[Status]%s' % (Fore.YELLOW, Fore.RESET))
        strategy.status()

        # TODO: connect to VPN

    def strategyForSSID(self, ssid):
        strategies = {
            "books and bagels" : BooksAndBagelsLoginStrategy,
            "Commonground" :     MeinHotspotLoginStrategy,
            "WIFIonICE" :        DeutscheBahnICELoginStrategy,
        }
        if ssid in strategies:
            return strategies[ssid]

        return DefaultLoginStrategy


class Tools:
    def sendHTTPSRequest(self, method, host, path, headers, body):
        return self.sendHTTPRequest(method, host, path, headers, body, True)

    def sendHTTPRequest(self, method, host, path, headers, body, secure=False):
        # Send request
        print('Connecting...\r', end='')
        # try:
        if secure:
            connection = http.client.HTTPSConnection(host)
        else:
            connection = http.client.HTTPConnection(host)
        # except:
        #     print('ERROR: Host "%s" is down.' % host)
        #     exit(-1)

        if headers == None:
            headers = {}
        # if body == None:
        #     body = ''
        connection.request(method, path, body, headers)

        #  Get response
        response = connection.getresponse()
        status = response.status
        head = response.getheaders()
        data = response.read()
        body = data.decode("utf-8")

        print('             \r', end='')
        return (status, head, body)

    def _exec(self, command):
        tokens = command.split(' ')
        process = subprocess.Popen(tokens, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdoutBytes, stderrBytes) = process.communicate()
        stdout = stdoutBytes.decode('utf-8')
        stderr = stderrBytes.decode('utf-8')
        return (stdout, stderr)

    def getSSID(self):
        (stdout, _) = self._exec("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I")
        result = stdout.split("\n")
        SSIDLines = [line for line in result if " SSID: " in line]
        if len(SSIDLines) < 1:
            return None

        SSID = SSIDLines[0].split(': ')[1]
        return SSID

    def getMACAddress(self):
        interface = 'en0'
        (stdout, _) = self._exec("ifconfig %s ether" % interface)
        result = stdout.split("\n")
        MACLines = [line for line in result if "ether " in line]
        if len(MACLines) < 1:
            return None

        MAC = MACLines[0].split('ether ')[1]
        return MAC
    
    def getGateway(self, destination='default'):
        (stdout, _) = self._exec("route -n get %s" % destination)
        result = stdout.split("\n")
        gatewayLines = [line for line in result if 'gateway: ' in line]
        if len(gatewayLines) < 1:
            return None

        gateway = gatewayLines[0].split('gateway: ')[1]
        return gateway
    
    def getIPForDomain(self, domain, dnsServer):
        (stdout, _) = self._exec("dig -4 -tA +nostats +nocomments +nocmd @%s %s" % (dnsServer, domain))
        result = stdout.split("\n")
        
        # Remove commented out lines
        result = [line for line in result if not line.startswith(';')]

        IP_lines = [line for line in result if 'A\t' in line]
        if len(IP_lines) < 1:
            return None

        IP = IP_lines[0].split('A\t')[1]
        return IP
    
    

    def printHTMLTable(self, html):
        tableContents = html
        tableContents = self.regexAfter('<\s*table[^>]*>', tableContents)
        tableContents = self.regexBefore('</\s*table\s*>', tableContents)

        tableData = []

        # Loop over '_tableContentsString' until no `<tr>`s are left
        _tableContentsString = self.regexAfter('<\s*tr[^>]*>', tableContents)
        while _tableContentsString:
            # Finds the ending `</tr>`
            _rowString = self.regexBefore('</\s*tr\s*>', _tableContentsString)

            # Empty array to store `col`s
            rowData = []

            # (Same logic as outer loop)
            # Loop over '_rowString' until no `<td>`s are left
            if _rowString:
                _rowString = self.regexAfter('<\s*td[^>]*>', _rowString)
                while _rowString:
                    col = self.regexBefore('</\s*td\s*>', _rowString)
                    col = re.sub('<\s*/?[A-z]+[^>]*>', '', col) # Remove all tags
                    rowData.append(col)
                    _rowString = self.regexAfter('<\s*td[^>]*>', _rowString)
            del _rowString

            # Add row data to table
            tableData.append(rowData)

            # Find next occurence and start over
            _tableContentsString = self.regexAfter('<\s*tr[^>]*>', _tableContentsString)
        
        # Get rid of the temp var
        del _tableContentsString


        # Determine number of columns (i.e. longest row)
        numberOfColumns = max([len(row) for row in tableData])

        # Determine longest columns of all rows
        columnLengths = [0] * numberOfColumns
        for row in tableData:
            _colLengths = [len(col) for col in row]
            for (i, colLen) in enumerate(_colLengths):
                columnLengths[i] = max(columnLengths[i], colLen)

        # Print table!
        for row in tableData:
            rowString = ''
            paddedRow = [col.ljust(columnLengths[i]) for (i, col) in enumerate(row)]
            print(" | ".join(paddedRow))
            
    
    def regexBefore(self, regex, input):
        match = re.search(regex, input)
        if not match: return None
        (start, end) = match.span(0)
        return input[:start]

    def regexAfter(self, regex, input):
        match = re.search(regex, input)
        if not match: return None
        (start, end) = match.span(0)
        return input[end:]

tools = None
if __name__ == '__main__':
    tools = Tools()
    HotspotLogin().main()