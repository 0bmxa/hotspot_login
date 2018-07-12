from colorama import Fore

from Tools import Tools
from DefaultLoginStrategy import DefaultLoginStrategy
from BooksAndBagelsLoginStrategy import BooksAndBagelsLoginStrategy
from MeinHotspotLoginStrategy import MeinHotspotLoginStrategy
from DeutscheBahnICELoginStrategy import DeutscheBahnICELoginStrategy


# FIXME: Not cool, I guess
TOOLS = Tools()

class HotspotLogin(object):
    strategies = {
        "books and bagels" : BooksAndBagelsLoginStrategy,
        "Commonground" :     MeinHotspotLoginStrategy,
        "WIFIonICE" :        DeutscheBahnICELoginStrategy,
    }

    def __init__(self):
        # Get SSID
        print('%s[SSID]%s' % (Fore.YELLOW, Fore.RESET))
        ssid = TOOLS.get_SSID()
        if not ssid:
            print('Not connected to WiFi')
            return
        print(ssid)

        # Get login strategy
        print('\n%s[Strategy]%s' % (Fore.YELLOW, Fore.RESET))
        strategy_class = self.strategy_for_ssid(ssid)
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

    def strategy_for_ssid(self, ssid):
        if ssid in self.strategies:
            return self.strategies[ssid]

        return DefaultLoginStrategy
