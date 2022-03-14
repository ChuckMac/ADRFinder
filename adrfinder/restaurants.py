import json
import re
import requests
from adrfinder import content_fetcher
from bs4 import BeautifulSoup
#from auth import Auth
from collections import OrderedDict

class Restaurants(object):

    def __init__(self):
        #self.header = Auth.get_auth()
        test='test'

    def get_dining_page(self):
        """
        Get the dining page for WDW
        """
        if hasattr(self, 'dining_page'):
            return self.dining_page

        request_headers = {}
        request_headers["Accept"] = "*/*"
        request_headers["X-Requested-With"] = "XMLHttpRequest"
        request_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        url='https://disneyworld.disney.go.com/dining/'

        try:
            r = requests.get(url=url,
                             headers=request_headers,
                             timeout=20,
                             verify=False)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(">> Request failed: {}".format(e))
            raise SystemExit(e)

        r.encoding = "utf-8"
        html_content = r.text

        dining_page = BeautifulSoup(html_content, 'html.parser')

        self.dining_page = dining_page
        return self.dining_page

    def get_restaurants(self):
        """
        Find all the restaurants at WDW
        Filter the ones that accept reservations

        return: dict { restaurant_name: restaurant_id;type }

        TODO: Probably is a better way to do this than
        scraping but haven't found an endpoint
        yet that doesn't require looping through every
        restaurant (300+ API hits)
        """

        dining_page = self.get_dining_page()

        ###
        ## Parse out restaurant ID to name correlation
        ###
        restautant_info = {}
        parent = dining_page.find('div', {"id" : 'finderListView'})
        for li in parent.find_all("li", attrs={'data-entityid' : True}):
            id = li['data-entityid']
            cardName = li.find('h2', {"class" : 'cardName'}).text
            restautant_info[id] = cardName

        ###
        ## Parse javascript data for restaurant reservation availability
        ###
        script_data = dining_page.find('script', {"id" : 'finderBlob'})

        for script_line in script_data.text.split('\n'):
            if "PEP.Finder.List =" in script_line:
                restaurant_value = '{%s}' % (script_line.partition('{')[2].rpartition('}')[0],)
                restaurant_data = json.loads(restaurant_value)

        ### 
        ## Parse filter 
        ## Restaurant should have "reservation-accepted" facet 
        ## id set to a value (no value seems to mean restaurant is closed)
        ## value set to 1 for reservations
        ###
        accepts_reservations = {}
        for card in restaurant_data['cards']:
            if "reservations-accepted" in  restaurant_data['cards'][card]['facets']:
                if "" != restaurant_data['cards'][card]['facets']['reservations-accepted']['id']:
                    if 1 == restaurant_data['cards'][card]['facets']['reservations-accepted']['value']:
                        id = restaurant_data['cards'][card]['id']
                        accepts_reservations[id] = restautant_info[id]

        return accepts_reservations

    def get_search_times(self):
        """
        Get the valid search times => values from disney dining page
        """

        dining_page = self.get_dining_page()

        search_info = OrderedDict()
        search_data = dining_page.find('span', {"id" : 'searchTime-wrapper'})
        for option in search_data.find_all("option"):
            search_info[option['value']] = option['label']
        
        return search_info

    def get_party_size(self):
        """
        Get the valid search times => values from disney dining page
        """

        dining_page = self.get_dining_page()

        search_info = OrderedDict()
        search_data = dining_page.find('span', {"id" : 'partySize-wrapper'})
        for option in search_data.find_all("option"):
            search_info[option['label']] = option['value']
        
        return search_info