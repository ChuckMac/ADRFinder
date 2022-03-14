import time
from flask import url_for
from urllib.request import urlopen
from . util import set_original_response, set_modified_response, live_server_setup


def test_check_watch_field_storage(client, live_server):
    set_original_response()
    live_server_setup(live_server)

    test_url = "http://somerandomsitewewatch.com"

    res = client.post(
        url_for("import_page"),
        data={"urls": test_url},
        follow_redirects=True
    )
    assert b"1 Imported" in res.data


    res = client.post(
        url_for("edit_page", uuid="first"),
        data={ "notification_urls": "json://myapi.com",
               "minutes_between_check": 126,
               "css_filter" : ".fooclass",
               "title" : "My title",
               "ignore_text" : "ignore this",
               "url": test_url,
               "tag": "woohoo",
               "headers": "curl:foo",
               'fetch_backend': "html_requests"
               },
        follow_redirects=True
    )
    assert b"Updated watch." in res.data

    res = client.get(
        url_for("edit_page", uuid="first"),
        follow_redirects=True
    )

    assert b"json://myapi.com" in res.data
    assert b"126" in res.data
    assert b".fooclass" in res.data
    assert b"My title" in res.data
    assert b"ignore this" in res.data
    assert b"http://somerandomsitewewatch.com" in res.data
    assert b"woohoo" in res.data
    assert b"curl: foo" in res.data



# Re https://github.com/chuckmac/adrfinder/issues/110
def test_check_recheck_global_setting(client, live_server):

    res = client.post(
        url_for("settings_page"),
        data={
               "minutes_between_check": 1566,
               'fetch_backend': "html_requests"
               },
        follow_redirects=True
    )
    assert b"Settings updated." in res.data

    # Now add a record

    test_url = "http://somerandomsitewewatch.com"

    res = client.post(
        url_for("import_page"),
        data={"urls": test_url},
        follow_redirects=True
    )
    assert b"1 Imported" in res.data

    # Now visit the edit page, it should have the default minutes

    res = client.get(
        url_for("edit_page", uuid="first"),
        follow_redirects=True
    )

    # Should show the default minutes
    assert b"change to another value if you want to be specific" in res.data
    assert b"1566" in res.data

    res = client.post(
        url_for("settings_page"),
        data={
               "minutes_between_check": 222,
                'fetch_backend': "html_requests"
               },
        follow_redirects=True
    )
    assert b"Settings updated." in res.data

    res = client.get(
        url_for("edit_page", uuid="first"),
        follow_redirects=True
    )

    # Should show the default minutes
    assert b"change to another value if you want to be specific" in res.data
    assert b"222" in res.data

    # Now change it specifically, it should show the new minutes
    res = client.post(
        url_for("edit_page", uuid="first"),
        data={"url": test_url,
              "minutes_between_check": 55,
              'fetch_backend': "html_requests"
              },
        follow_redirects=True
    )

    res = client.get(
        url_for("edit_page", uuid="first"),
        follow_redirects=True
    )
    assert b"55" in res.data

    # Now submit an empty field, it should give back the default global minutes
    res = client.post(
        url_for("settings_page"),
        data={
               "minutes_between_check": 666,
                'fetch_backend': "html_requests"
               },
        follow_redirects=True
    )
    assert b"Settings updated." in res.data

    res = client.post(
        url_for("edit_page", uuid="first"),
        data={"url": test_url,
              "minutes_between_check": "",
              'fetch_backend': "html_requests"
              },
        follow_redirects=True
    )

    assert b"Updated watch." in res.data

    res = client.get(
        url_for("edit_page", uuid="first"),
        follow_redirects=True
    )
    assert b"666" in res.data

