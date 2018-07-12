#!/usr/bin/env python3

import http.client
import urllib
import datetime
import subprocess
from colorama import Fore
import re
import socket


class LoginStrategyType(object):
    def name(self): raise NotImplementedError()
    def check_preconditions(self): return (True, None) # (success, message)
    def login(self): raise NotImplementedError()
    def status(self): raise NotImplementedError()
    def logout(self): raise NotImplementedError()

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


class DefaultLoginStrategy(LoginStrategyType):
    def name(self):
        return "Default"

    def login(self):
        # Find captive portal URL
        print("1. Looking for a captive portal")

        headers = { 'host': 'neverssl.com' }
        host_IP = '13.32.158.44'
        (status, head, body) = tools.send_HTTP_request('GET', host_IP, '/', headers, None)
        location = [field[1] for field in head if field[0] == 'Location']
        if len(location) < 1:
            print("No captive portal found.")
            return True

        # Found a captive portal
        captive_portal_URL = location[0]
        debugprint("Found captive portal at: %s" % captive_portal_URL)

        captive_portal_IP = None

        # Replace (potential) domain name with IP, because I'm using my own DNS
        print('2. Replacing domain name with IP')

        real_hostname = urllib.parse.urlparse(captive_portal_URL).hostname
        captive_portal_URL = tools.check_and_replace_domain(captive_portal_URL)
        debugprint('URL is now: %s' % captive_portal_URL)

        # Get the captive portal HTML
        secure = False #(url_parts.scheme == 'https')
        url_parts = urllib.parse.urlparse(captive_portal_URL)
        captive_portal_IP = url_parts.hostname
        path = url_parts.geturl().split(captive_portal_IP)[1]
        headers = { 'host': real_hostname }
        (_, head, body) = tools.send_HTTP_request('GET', captive_portal_IP, path, headers, None, secure)
        
        # Check if a redirect is requested
        location = [field[1] for field in head if field[0] == 'Location']
        if len(location) > 0:
            print('  Portal wants to redirect to:\n  %s%s%s' % (Fore.YELLOW, location[0], Fore.RESET))
            print('Redirects not yet supported.')
            return

        
        #
        # Print it fancy
        #

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

        tools.get_MAC_address()

        # Get SSID
        print('%s[SSID]%s' % (Fore.YELLOW, Fore.RESET))
        ssid = tools.get_SSID()
        if not ssid:
            print('Not connected to WiFi')
            return
        print(ssid)

        # Get login strategy
        print('\n%s[Strategy]%s' % (Fore.YELLOW, Fore.RESET))
        strategy_class = self.strategy_for_SSID(ssid)
        strategy = strategy_class()
        print("%s strategy" % strategy.name())

        # Check Preconditions
        (preconditions_success, preconditions_message) = strategy.check_preconditions()
        if preconditions_message:
            print('\n%s[Preconditions]%s' % (Fore.YELLOW, Fore.RESET))
            print(preconditions_message)
        if not preconditions_success:
            return

        # Login
        print('\n%s[Login]%s' % (Fore.YELLOW, Fore.RESET))
        login_success = strategy.login()
        if not login_success:
            print('Login was not successful.')
            return

        # Status
        print('\n%s[Status]%s' % (Fore.YELLOW, Fore.RESET))
        strategy.status()

        # TODO: connect to VPN

    def strategy_for_SSID(self, ssid):
        strategies = {
            "books and bagels" : BooksAndBagelsLoginStrategy,
            "Commonground" :     MeinHotspotLoginStrategy,
            "WIFIonICE" :        DeutscheBahnICELoginStrategy,
        }
        if ssid in strategies:
            return strategies[ssid]

        return DefaultLoginStrategy


class Tools:
    def send_HTTPS_request(self, method, host, path, headers, body):
        return self.send_HTTP_request(method, host, path, headers, body, True)

    def send_HTTP_request(self, method, host, path, headers, body, secure=False):
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

        print('             \r', end='') # Erase previous 'Connecting...' output
        return (status, head, body)

    def _exec(self, command):
        tokens = command.split(' ')
        process = subprocess.Popen(tokens, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout_bytes, stderr_bytes) = process.communicate()
        stdout = stdout_bytes.decode('utf-8')
        stderr = stderr_bytes.decode('utf-8')
        return (stdout, stderr)

    def get_SSID(self):
        (stdout, _) = self._exec("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I")
        result = stdout.split("\n")
        SSIDLines = [line for line in result if " SSID: " in line]
        if len(SSIDLines) < 1:
            return None

        SSID = SSIDLines[0].split(': ')[1]
        return SSID

    def get_MAC_address(self):
        interface = 'en0'
        (stdout, _) = self._exec("ifconfig %s ether" % interface)
        result = stdout.split("\n")
        MACLines = [line for line in result if "ether " in line]
        if len(MACLines) < 1:
            return None

        MAC = MACLines[0].split('ether ')[1]
        return MAC
    
    def get_gateway(self, destination='default'):
        (stdout, _) = self._exec("route -n get %s" % destination)
        result = stdout.split("\n")
        gateway_lines = [line for line in result if 'gateway: ' in line]
        if len(gateway_lines) < 1:
            return None

        gateway = gateway_lines[0].split('gateway: ')[1]
        return gateway

    def check_and_replace_domain(self, URL):
        url_parts = urllib.parse.urlparse(URL)
        hostname = url_parts.hostname

        # Check if hostname is an IP already, if not, resolve
        if self.is_IP(hostname):
            return URL
        
        # Get default gateway (which is hopefully a DNS server)
        default_gateway = tools.get_gateway()

        # Get portal IP
        IP = tools.get_IP_for_domain(hostname, default_gateway)

        if not IP:
            return URL

        url_parts._replace('hostname', IP)

        new_URL = url_parts.geturl()

        debugprint("Replaced '%s' with '%s'" % (hostname, IP))
        debugprint("URL is now: %s" % new_URL)

        return new_URL

    def is_IP(self, host):
        try:
            socket.inet_aton(host)
            return True

        except socket.error:
            return False

    def get_IP_for_domain(self, domain, dns_server):
        (stdout, _) = self._exec("dig -4 -tA +nostats +nocomments +nocmd @%s %s" % (dns_server, domain))
        result = stdout.split("\n")
        
        # Remove commented out lines
        result = [line for line in result if not line.startswith(';')]

        IP_lines = [line for line in result if 'A\t' in line]
        if len(IP_lines) < 1:
            print("ERROR: Couldn't resolve domain '%s'." % domain)
            return None

        IP = IP_lines[0].split('A\t')[1]
        return IP
    
    

    def print_HTML_table(self, html):
        table_contents = html
        table_contents = self.regex_after('<\s*table[^>]*>', table_contents)
        table_contents = self.regex_before('</\s*table\s*>', table_contents)

        table_data = []

        # Loop over '_table_contents_string' until no `<tr>`s are left
        _table_contents_string = self.regex_after('<\s*tr[^>]*>', table_contents)
        while _table_contents_string:
            # Finds the ending `</tr>`
            _row_string = self.regex_before('</\s*tr\s*>', _table_contents_string)

            # Empty array to store `col`s
            row_data = []

            # (Same logic as outer loop)
            # Loop over '_row_string' until no `<td>`s are left
            if _row_string:
                _row_string = self.regex_after('<\s*td[^>]*>', _row_string)
                while _row_string:
                    col = self.regex_before('</\s*td\s*>', _row_string)
                    col = re.sub('<\s*/?[A-z]+[^>]*>', '', col) # Remove all tags
                    row_data.append(col)
                    _row_string = self.regex_after('<\s*td[^>]*>', _row_string)
            del _row_string

            # Add row data to table
            table_data.append(row_data)

            # Find next occurence and start over
            _table_contents_string = self.regex_after('<\s*tr[^>]*>', _table_contents_string)
        
        # Get rid of the temp var
        del _table_contents_string


        # Determine number of columns (i.e. longest row)
        number_of_columns = max([len(row) for row in table_data])

        # Determine longest columns of all rows
        column_lengths = [0] * number_of_columns
        for row in table_data:
            _col_lengths = [len(col) for col in row]
            for (i, col_len) in enumerate(_col_lengths):
                column_lengths[i] = max(column_lengths[i], col_len)

        # Print table!
        for row in table_data:
            row_string = ''
            padded_row = [col.ljust(column_lengths[i]) for (i, col) in enumerate(row)]
            print(" | ".join(padded_row))
            
    
    def regex_before(self, regex, input):
        match = re.search(regex, input)
        if not match: return None
        (start, end) = match.span(0)
        return input[:start]

    def regex_after(self, regex, input):
        match = re.search(regex, input)
        if not match: return None
        (start, end) = match.span(0)
        return input[end:]

def debugprint(message):
    print('  %s%s%s' % (Fore.LIGHTBLACK_EX, message, Fore.RESET))

tools = None
if __name__ == '__main__':
    tools = Tools()
    HotspotLogin().main()