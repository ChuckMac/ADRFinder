#!/usr/bin/python3

import time
from flask import url_for
from . util import live_server_setup



def test_trigger_functionality(client, live_server):

    live_server_setup(live_server)

    # Give the endpoint time to spin up
    time.sleep(1)

    # Add our URL to the import page
    res = client.post(
        url_for("import_page"),
        data={"urls": "https://adrfinder.com"},
        follow_redirects=True
    )
    assert b"1 Imported" in res.data


    res = client.get(
        url_for("api_clone", uuid="first"),
        follow_redirects=True
    )

    assert b"Cloned." in res.data
