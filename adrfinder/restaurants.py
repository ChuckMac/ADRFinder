import json
import http.client
import datetime
from collections import OrderedDict


class Restaurants(object):

    def __init__(self):
        self.connection = http.client.HTTPSConnection("disneyworld.disney.go.com")
        self.header = self.get_auth_cookie()

    def get_auth_cookie(self):
        """
        Get the authorization cookie
        """
        payload = "{}"
        headers = {}

        try:
            self.connection.request("POST", "/finder/api/v1/authz/public", payload, headers)
        except Exception as e:
            print(">> Request failed, Unable to get AUTH cookie: {}".format(e))
            raise SystemExit(e)

        response = self.connection.getresponse()
        if response.status != 200:
            print(">> Request failed, Non-200 received getting AUTH cookie: {}".format(response.status))
            raise SystemExit(response.status)

        response.read()
        headers['Cookie'] = response.getheader('set-cookie')

        return headers

    def get_dining_data(self):
        """
        Get the dining info for WDW
        """
        if hasattr(self, 'dining_data'):
            return self.dining_data

        yyyymmdd = datetime.datetime.today().strftime('%Y-%m-%d')

        try:
            self.connection.request("GET", "/finder/api/v1/explorer-service/list-ancestor-entities/wdw/80007798;entityType=destination/" + yyyymmdd + "/dining", headers=self.header)
        except Exception as e:
            print(">> Request failed, Unable to get Dining Data: {}".format(e))
            raise SystemExit(e)

        response = self.connection.getresponse()
        if response.status != 200:
            print(">> Request failed, Non-200 received getting Dining Data: {}".format(response.status))
            raise SystemExit(response.status)

        data = response.read()

        self.dining_data = json.loads(data.decode("utf-8"))
        return self.dining_data

    def get_restaurants(self):
        """
        Find all the restaurants at WDW
        Filter the ones that accept reservations

        return: dict { restaurant_name: restaurant_id;type }

        """

        dining_data = self.get_dining_data()

        restaurant_results = {}

        for result in dining_data['results']:
            accepts_reservations = False

            for facet in result['facets']:
                for flag in result['facets'][facet]:
                    if 'reservations-accepted' == flag:
                        accepts_reservations = True

            if accepts_reservations is True:
                restaurant_results[result['id']] = result['name']

        return restaurant_results

    def get_search_times(self):
        """
        Get the valid search times => values from disney dining page
        """

        dining_data = self.get_dining_data()

        search_times = OrderedDict()

        for mealPeriods in dining_data['filters']['diningFormFilter']['mealPeriods']:
            search_times[mealPeriods['key']] = mealPeriods['value']

        for mealTimes in dining_data['filters']['diningFormFilter']['times']:
            search_times[mealTimes['key']] = mealTimes['value']

        return search_times

    def get_party_size(self):
        """
        Hardcode max party
        """

        search_info = OrderedDict()
        for n in range(1, 51):
            search_info[n] = n

        return search_info
