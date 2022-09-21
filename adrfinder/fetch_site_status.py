import urllib3
import urllib.parse
import json
import http.client
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Some common stuff here that can be moved to a base class
class perform_site_check():

    def __init__(self, *args, datastore, **kwargs):
        super().__init__(*args, **kwargs)
        self.datastore = datastore
        self.headers = self.get_auth_cookie()

    def get_auth_cookie(self):
        """
        Get the authorization cookie
        """

        refresh_time = self.datastore.data['cache']['auth']['auth_token_expiry']
        if type(refresh_time) != int:
            refresh_time = 0

        headers = {}
        if refresh_time == '' or refresh_time <= int(time.time()):
            payload = "{}"

            connection = http.client.HTTPSConnection("disneyworld.disney.go.com")

            try:
                connection.request("POST", "/finder/api/v1/authz/public", payload, headers)
            except Exception as e:
                connection.close()
                print(">> Request failed, Unable to get AUTH cookie: {}".format(e))
                raise Exception("Request failed, Unable to get AUTH cookie: {}".format(e))

            response = connection.getresponse()
            if response.status != 200:
                connection.close()
                print(">> Request failed, Non-200 received getting AUTH cookie: {}".format(response.status))
                raise Exception("Request failed, Non-200 received getting AUTH cookie: {}".format(response.status))

            response.read()
            connection.close()

            cookie = response.getheader('set-cookie')
            headers['Cookie'] = cookie

            expires = int(time.time()) + 14000
            self.datastore.update_auth(cookie, expires)

        else:
            token = self.datastore.data['cache']['auth']['auth_token']
            headers['Cookie'] = token

        return headers

    def run(self, uuid):

        base_link = 'https://disneyworld.disney.go.com/dining-reservation/setup-order/table-service/?offerId[]='
        base_suffix = '&offerOrigin=/dining/'

        available_detected = False

        # Unset any existing notification error
        restaurant = self.datastore.get_val(uuid, 'restaurant')
        date = self.datastore.get_val(uuid, 'date')
        party_size = self.datastore.get_val(uuid, 'party_size')
        search_time = urllib.parse.quote(self.datastore.get_val(uuid, 'search_time'))

        if '%3A' in search_time:
            endpoint = "/finder/api/v1/explorer-service/dining-availability-list/false/wdw/80007798;entityType=destination/" + date + "/" + party_size + "/?searchTime=" + search_time
        else:
            endpoint = "/finder/api/v1/explorer-service/dining-availability-list/false/wdw/80007798;entityType=destination/" + date + "/" + party_size + "/?mealPeriod=" + search_time

        connection = http.client.HTTPSConnection("disneyworld.disney.go.com")

        try:
            connection.request("GET", endpoint, headers=self.headers)
        except Exception as e:
            connection.close()
            print(">> Request failed, Unable to get reservation data: {}".format(e))
            raise Exception("Request failed, Unable to get reservation data: {}".format(e))

        response = connection.getresponse()
        if response.status != 200:
            connection.close()
            print(">> Request failed, Non-200 received getting reservation data: {}".format(response.status))
            print(">> Request url: https://disneyworld.disney.go.com{}".format(endpoint))
            raise Exception("Request failed, Non-200 received getting reservation data: {}".format(response.status))

        data = response.read()
        connection.close()
        json_reservations = json.loads(data.decode("utf-8"))

        offers = []
        if restaurant in json_reservations['availability']:
            if json_reservations['availability'][restaurant]['hasAvailability'] is True:
                available_detected = True

                for offer in json_reservations['availability'][restaurant]['singleLocation']['offers']:
                    offer_link = base_link + offer['url'] + base_suffix
                    offers.append({'time': offer['label'], 'url': offer_link})
        else:
            raise Exception("Restaurant ID not found in data: {}".format(restaurant))

        return available_detected, offers
