#!/usr/bin/python3

import time
from flask import url_for
from . util import live_server_setup


def set_original_ignore_response():
    test_return_data = """<html>
       <body>
     Some initial text</br>
     <p>Which is across multiple lines</p>
     </br>
     So let's see what happens.  </br>
     </body>
     </html>

    """

    with open("test-datastore/endpoint-content.txt", "w") as f:
        f.write(test_return_data)



def test_trigger_regex_functionality(client, live_server):

    live_server_setup(live_server)

    sleep_time_for_fetch_thread = 3

    set_original_ignore_response()

    # Give the endpoint time to spin up
    time.sleep(1)

    # Add our URL to the import page
    test_url = url_for('test_endpoint', _external=True)
    res = client.post(
        url_for("import_page"),
        data={"urls": test_url},
        follow_redirects=True
    )
    assert b"1 Imported" in res.data

    # Trigger a check
    client.get(url_for("api_watch_checknow"), follow_redirects=True)

    # Give the thread time to pick it up
    time.sleep(sleep_time_for_fetch_thread)

    # It should report nothing found (just a new one shouldnt have anything)
    res = client.get(url_for("index"))
    assert b'unviewed' not in res.data

    ### test regex
    res = client.post(
        url_for("edit_page", uuid="first"),
        data={"url": test_url,
              "fetch_backend": "html_requests"},
        follow_redirects=True
    )


    with open("test-datastore/endpoint-content.txt", "w") as f:
        f.write("some new noise")

    client.get(url_for("api_watch_checknow"), follow_redirects=True)
    time.sleep(sleep_time_for_fetch_thread)

    # It should report nothing found (nothing should match the regex)
    res = client.get(url_for("index"))
    assert b'unviewed' not in res.data

    with open("test-datastore/endpoint-content.txt", "w") as f:
        f.write("regex test123<br/>\nsomething 123")

    client.get(url_for("api_watch_checknow"), follow_redirects=True)
    time.sleep(sleep_time_for_fetch_thread)
    res = client.get(url_for("index"))
    assert b'unviewed' in res.data