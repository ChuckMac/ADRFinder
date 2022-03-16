#!/usr/bin/python3

from adrfinder.restaurants import Restaurants


def test_restaurant_list(app, client):
    restaurants = Restaurants()
    rest_list = restaurants.get_restaurants()

    assert type(rest_list) is dict
    assert len(rest_list) > 5

    # check the ID contains a semicolon and
    # restaurant name is not empty
    for id, name in rest_list.items():
        assert (';' in id)
        assert len(name) > 0
