import datetime

from strategies.MeinHotspotLoginStrategy import MeinHotspotLoginStrategy


class BooksAndBagelsLoginStrategy(MeinHotspotLoginStrategy):
    def name(self):
        return "BooksAndBagels"

    def check_preconditions(self):
        return (True, 'Hotspot times seem to be not important for this script.')
        # # Fine Bagels Hotspot on weekends:
        # # Saturday only from 17:00, Sunday from 19:00 on
        # now = datetime.datetime.now()
        # if (now.weekday() == 5 and now.hour < 17) or \
        #    (now.weekday() == 6 and now.hour < 19):
        #     return (False, 'The hotspot is offline.')
        # return (True, None)
