#!/usr/bin/python3

from adrfinder import fetch_site_status


def test_wdw_auth(app, client):
    datastore = ADRFinderStore_test()
    update_handler = fetch_site_status.perform_site_check(datastore=datastore)
    request_header = update_handler.get_auth_cookie()
    assert len(request_header["Cookie"]) > 7


class ADRFinderStore_test:

    def __init__(self):
        self.data = {
            'cache': {
                'auth': {
                    'auth_token_expiry': 0,
                }
            }
        }

    def update_auth(self, auth_token, auth_token_expiry):
        return True
