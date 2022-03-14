import time
import urllib3
import json
import requests
import time
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Some common stuff here that can be moved to a base class
class perform_site_check():

    def __init__(self, *args, datastore, **kwargs):
        super().__init__(*args, **kwargs)
        self.datastore = datastore

    def get_auth_header(self):
        """
        Get disney OATH bearer token

        return: dict { Authorization: token, User-Agent: user-agent }
        """
        refresh_time = self.datastore.data['cache']['auth']['auth_token_expiry']
        if type(refresh_time) != int:
            refresh_time = 0
        refresh_time = refresh_time - 60 ## 60 second buffer

        header = ''
        user_agent = "ADRFinder/0.1 (1.4.1/8a21c5927a273a038fb3b66ec29c86425e871b11)"

        if refresh_time == '' or refresh_time <= int(time.time()):
            url = "https://disneyworld.disney.go.com/authentication/get-client-token"
            request_headers = {"User-Agent":user_agent,"Content-Type":"application/json","Accept":"multipart/related"}

            r = requests.get(url, headers=request_headers, verify=False)
            response = json.loads(r.content)

            expires = datetime.now() + timedelta(seconds=response['expires_in'])
            self.datastore.update_auth(response['access_token'], int(expires.timestamp()))

            header = {"Authorization":"BEARER " + response['access_token'], "User-Agent":user_agent}

        else: 
            token = self.datastore.data['cache']['auth']['auth_token']
            header = {"Authorization":"BEARER " + token, "User-Agent":user_agent}

        return header


    def run(self, uuid):

        base_link = 'https://disneyworld.disney.go.com/dining-reservation/setup-order/table-service/?offerId[]='
        base_suffix = '&offerOrigin=/dining/'

        available_detected = False

        # Unset any existing notification error
        restaurant = self.datastore.get_val(uuid, 'restaurant')
        date = self.datastore.get_val(uuid, 'date')
        party_size = self.datastore.get_val(uuid, 'party_size')
        search_time = self.datastore.get_val(uuid, 'search_time')

        request_header = self.get_auth_header()
        base_url = "https://api.wdpro.disney.go.com/explorer-service/public/finder/dining-availability/"

        url = base_url + restaurant + "?searchDate=" + date + "&partySize=" + str(party_size) + "&mealPeriod=" + str(search_time)

        r = requests.get(url, headers=request_header, verify=False)
        data = json.loads(r.content)

        offers = []
        if "availability" in data:
            if restaurant in data["availability"]:
                for available in data["availability"][restaurant]["availableTimes"]:
                    for offer in available["offers"]:
                        available_detected = True
                        offer_time = datetime.strptime(offer['time'], "%H:%M")
                        converted_time = offer_time.strftime("%I:%M %p").lstrip('0')
                        offer_link = base_link + offer['url'] + base_suffix
                        offers.append({'time': converted_time, 'url': offer_link})

        return available_detected, offers
