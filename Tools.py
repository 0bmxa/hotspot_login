import subprocess
import http.client
from colorama import Fore


def debugprint(message):
    print('  %s%s%s' % (Fore.LIGHTBLACK_EX, message, Fore.RESET))

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
