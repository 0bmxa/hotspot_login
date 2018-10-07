import urllib

from LoginStrategyType import LoginStrategyType
from Tools import *
import re as regex


# FIXME: Not cool, I guess
tools = Tools()

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
        form_start = regex.search('<\s*form[^>]*>', body)
        if form_start:
            (form_start_index, _) = form_start.span(0)

            form_end = regex.search('</\s*form\s*>', body)
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
