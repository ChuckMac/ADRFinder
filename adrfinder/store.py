from os import unlink, path, mkdir
import json
import uuid as uuid_builder
from threading import Lock
from copy import deepcopy
from datetime import datetime, timedelta

import logging
import time
import threading
import os

from adrfinder.notification import default_notification_format, default_notification_body, default_notification_title

# Is there an existing library to ensure some data store (JSON etc) is in sync with CRUD methods?
# Open a github issue if you know something :)
# https://stackoverflow.com/questions/6190468/how-to-trigger-function-on-value-change
class ADRFinderStore:
    lock = Lock()

    def __init__(self, datastore_path="/datastore", include_default_watches=True, version_tag="0.0.0"):
        # Should only be active for docker
        # logging.basicConfig(filename='/dev/stdout', level=logging.INFO)
        self.needs_write = False
        self.datastore_path = datastore_path
        self.json_store_path = "{}/url-watches.json".format(self.datastore_path)
        self.stop_thread = False

        self.__data = {
            'note': "Hello! If you change this file manually, please be sure to restart your ADRFinder instance!",
            'watching': {},
            'settings': {
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Encoding': 'gzip, deflate',  # No support for brolti in python requests yet.
                    'Accept-Language': 'en-GB,en-US;q=0.9,en;'
                },
                'requests': {
                    'timeout': 15,  # Default 15 seconds
                    'minutes_between_check': 20,  # Default 20 minutes
                    'minutes_before_restaurant_refresh': 60 * 8,  # Default 8 hours
                    'workers': 10  # Number of threads, lower is better for slow connections
                },
                'application': {
                    'password': False,
                    'base_url' : None,
                    'notification_urls': [], # Apprise URL list
                    # Custom notification content
                    'notification_title': default_notification_title,
                    'notification_body': default_notification_body,
                    'notification_format': default_notification_format,
                    'pause_length': 0
                }
            },
            'cache': {
                'auth': {
                    'auth_token': None,
                    'auth_token_expiry': None,
                    'auth_token_refresh_time': 60
                },
                'restaurants': {
                    'last_updated': None,
                    'data': {},
                    'times': {}
                }
            }
        }

        # Base definition for all watchers
        self.generic_definition = {
            'restaurant': None,
            'date': None,
            'party_size': None,
            'search_time': None,
            'tag': None,
            'last_checked': 0,
            'last_changed': 0,
            'paused': False,
            'paused_until': None,
            'last_viewed': 0,  # history key value of the last viewed via the [diff] link
            'newest_history_key': "",
            'total_searches': 0,
            'title': None,
            # Re #110, so then if this is set to None, we know to use the default value instead
            # Requires setting to None on submit if it's the same as the default
            'minutes_between_check': None,
            'pause_length': None,
            'previous_md5': "",
            'uuid': str(uuid_builder.uuid4()),
            'body': None,
            'method': 'GET',
            'history': {},  # Dict of timestamp and output stripped filename
            # Custom notification content
            'notification_urls': [], # List of URLs to add to the notification Queue (Usually AppRise)
            'notification_title': default_notification_title,
            'notification_body': default_notification_body,
            'notification_format': default_notification_format,
        }

        if path.isfile('adrfinder/source.txt'):
            with open('adrfinder/source.txt') as f:
                # Should be set in Dockerfile to look for /source.txt , this will give us the git commit #
                # So when someone gives us a backup file to examine, we know exactly what code they were running.
                self.__data['build_sha'] = f.read()

        try:
            # @todo retest with ", encoding='utf-8'"
            with open(self.json_store_path) as json_file:
                from_disk = json.load(json_file)

                # @todo isnt there a way todo this dict.update recursively?
                # Problem here is if the one on the disk is missing a sub-struct, it wont be present anymore.
                if 'watching' in from_disk:
                    self.__data['watching'].update(from_disk['watching'])

                if 'app_guid' in from_disk:
                    self.__data['app_guid'] = from_disk['app_guid']

                if 'settings' in from_disk:

                    if 'requests' in from_disk['settings']:
                        self.__data['settings']['requests'].update(from_disk['settings']['requests'])

                    if 'application' in from_disk['settings']:
                        self.__data['settings']['application'].update(from_disk['settings']['application'])

                if 'cache' in from_disk:
                    if 'auth' in from_disk['cache']:
                        self.__data['cache']['auth'].update(from_disk['cache']['auth'])

                    if 'restaurants' in from_disk['cache']:
                        self.__data['cache']['restaurants'].update(from_disk['cache']['restaurants'])


                # Reinitialise each `watching` with our generic_definition in the case that we add a new var in the future.
                # @todo pretty sure theres a python we todo this with an abstracted(?) object!
                for uuid, watch in self.__data['watching'].items():
                    _blank = deepcopy(self.generic_definition)
                    _blank.update(watch)
                    self.__data['watching'].update({uuid: _blank})
                    self.__data['watching'][uuid]['newest_history_key'] = self.get_newest_history_key(uuid)
                    print("Watching:", uuid, self.__data['watching'][uuid]['restaurant'])

        # First time ran, doesnt exist.
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            if include_default_watches:
                print("Creating JSON store at", self.datastore_path)

        self.__data['version_tag'] = version_tag

        # Convert date to datetime object
        #for uuid, v in self.__data['watching'].items():
        #    print(">> Converting date")
        #    print(self.__data['watching'][uuid]['date'])
        #    self.__data['watching'][uuid]['date'] = datetime.datetime.strptime(self.__data['watching'][uuid]['date'], '%Y-%m-%d').date()


        # Helper to remove password protection
        password_reset_lockfile = "{}/removepassword.lock".format(self.datastore_path)
        if path.isfile(password_reset_lockfile):
            self.__data['settings']['application']['password'] = False
            unlink(password_reset_lockfile)

        if not 'app_guid' in self.__data:
            import sys
            import os
            if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
                self.__data['app_guid'] = "test-" + str(uuid_builder.uuid4())
            else:
                self.__data['app_guid'] = str(uuid_builder.uuid4())

        # Generate the URL access token for RSS feeds
        if not 'rss_access_token' in self.__data['settings']['application']:
            import secrets
            secret = secrets.token_hex(16)
            self.__data['settings']['application']['rss_access_token'] = secret

        self.needs_write = True

        # Finally start the thread that will manage periodic data saves to JSON
        save_data_thread = threading.Thread(target=self.save_datastore).start()

    # Returns the newest key, but if theres only 1 record, then it's counted as not being new, so return 0.
    def get_newest_history_key(self, uuid):
        if len(self.__data['watching'][uuid]['history']) == 1:
            return 0

        dates = list(self.__data['watching'][uuid]['history'].keys())
        # Convert to int, sort and back to str again
        # @todo replace datastore getter that does this automatically
        dates = [int(i) for i in dates]
        dates.sort(reverse=True)
        if len(dates):
            # always keyed as str
            return str(dates[0])

        return 0

    def set_last_viewed(self, uuid, timestamp):
        self.data['watching'][uuid].update({'last_viewed': int(timestamp)})
        self.needs_write = True

    def update_auth(self, auth_key, auth_expiry):

        with self.lock:
            self.data['cache']['auth']['auth_token'] = auth_key
            self.data['cache']['auth']['auth_token_expiry'] = auth_expiry

        self.needs_write = True

    def pause_watch(self, uuid, pause):
        with self.lock:
            self.__data['watching'][uuid]['paused'] = True

            if pause == "0":
                self.__data['watching'][uuid]['paused_until'] = None
            else:
                expires = datetime.now() + timedelta(minutes=int(pause))
                self.__data['watching'][uuid]['paused_until'] = int(expires.timestamp())

        self.needs_write = True

    def update_watch(self, uuid, data):

        with self.lock:

            # In python 3.9 we have the |= dict operator, but that still will lose data on nested structures...
            for dict_key, d in self.generic_definition.items():
                if isinstance(d, dict):
                    if data is not None and dict_key in data:
                        self.__data['watching'][uuid][dict_key].update(data[dict_key])
                        del (data[dict_key])

            self.__data['watching'][uuid].update(data)
            self.__data['watching'][uuid]['newest_history_key'] = self.get_newest_history_key(uuid)

        self.needs_write = True

    @property
    def data(self):
        has_unviewed = False
        for uuid, v in self.__data['watching'].items():
            self.__data['watching'][uuid]['newest_history_key'] = self.get_newest_history_key(uuid)
            if int(v['newest_history_key']) <= int(v['last_viewed']):
                self.__data['watching'][uuid]['viewed'] = True

            else:
                self.__data['watching'][uuid]['viewed'] = False
                has_unviewed = True

        # Re #152, Return env base_url if not overriden, @todo also prefer the proxy pass url
        env_base_url = os.getenv('BASE_URL','')
        if not self.__data['settings']['application']['base_url']:
          self.__data['settings']['application']['base_url'] = env_base_url.strip('" ')

        self.__data['has_unviewed'] = has_unviewed

        return self.__data

    def get_all_tags(self):
        tags = []
        for uuid, watch in self.data['watching'].items():

            # Support for comma separated list of tags.
            for tag in watch['tag'].split(','):
                tag = tag.strip()
                if tag not in tags:
                    tags.append(tag)

        tags.sort()
        return tags

    def unlink_history_file(self, path):
        try:
            unlink(path)
        except (FileNotFoundError, IOError):
            pass

    # Delete a single watch by UUID
    def delete(self, uuid):
        with self.lock:
            if uuid == 'all':
                self.__data['watching'] = {}

            else:
                del self.data['watching'][uuid]

            self.needs_write = True

    # Clone a watch by UUID
    def clone(self, uuid):
        restaurant = self.data['watching'][uuid]['restaurant']
        date = self.data['watching'][uuid]['date']
        party_size = self.data['watching'][uuid]['party_size']
        search_time = self.data['watching'][uuid]['search_time']
        tag = self.data['watching'][uuid]['tag']
        extras = self.data['watching'][uuid]
        new_uuid = self.add_watch(restaurant=restaurant, date=date, party_size=party_size, search_time=search_time, tag=tag, extras=extras)

        return new_uuid

    def watch_exists(self, restaurant, date, party_size, search_time):
        for watch in self.data['watching'].values():
            if watch['restaurant'] == restaurant and watch['date'] == date and watch['party_size'] == party_size and watch['search_time'] == search_time:
                return True

        return False

    def url_exists(self, url):

        # Probably their should be dict...
        for watch in self.data['watching'].values():
            if watch['url'] == url:
                return True

        return False

    def get_val(self, uuid, val):
        # Probably their should be dict...
        return self.data['watching'][uuid].get(val)

    # Remove a watchs data but keep the entry (URL etc)
    def scrub_watch(self, uuid, limit_timestamp = False):

        import hashlib
        del_timestamps = []

        changes_removed = 0

        for timestamp, path in self.data['watching'][uuid]['history'].items():
            if not limit_timestamp or (limit_timestamp is not False and int(timestamp) > limit_timestamp):
                self.unlink_history_file(path)
                del_timestamps.append(timestamp)
                changes_removed += 1

        if not limit_timestamp:
            self.data['watching'][uuid]['last_checked'] = 0
            self.data['watching'][uuid]['last_changed'] = 0
            self.data['watching'][uuid]['previous_md5'] = ""


        for timestamp in del_timestamps:
            del self.data['watching'][uuid]['history'][str(timestamp)]

            # If there was a limitstamp, we need to reset some meta data about the entry
            # This has to happen after we remove the others from the list
            if limit_timestamp:
                newest_key = self.get_newest_history_key(uuid)
                if newest_key:
                    self.data['watching'][uuid]['last_checked'] = int(newest_key)
                    # @todo should be the original value if it was less than newest key
                    self.data['watching'][uuid]['last_changed'] = int(newest_key)
                    try:
                        with open(self.data['watching'][uuid]['history'][str(newest_key)], "rb") as fp:
                            content = fp.read()
                        self.data['watching'][uuid]['previous_md5'] = hashlib.md5(content).hexdigest()
                    except (FileNotFoundError, IOError):
                        self.data['watching'][uuid]['previous_md5'] = ""
                        pass

        self.needs_write = True
        return changes_removed

    def add_watch(self, restaurant, date, party_size, search_time, tag="", extras=None):
        if extras is None:
            extras = {}

        with self.lock:
            # @todo use a common generic version of this
            new_uuid = str(uuid_builder.uuid4())
            _blank = deepcopy(self.generic_definition)
            _blank.update({
                'restaurant': restaurant,
                'date': date,
                'party_size': party_size,
                'search_time': search_time,
                'tag': tag
            })

            # Incase these are copied across, assume it's a reference and deepcopy()
            apply_extras = deepcopy(extras)
            for k in ['uuid', 'history', 'last_checked', 'last_changed', 'newest_history_key', 'previous_md5', 'viewed']:
                if k in apply_extras:
                    del apply_extras[k]

            _blank.update(apply_extras)

            self.data['watching'][new_uuid] = _blank

        self.sync_to_json()
        return new_uuid

    # Save some text file to the appropriate path and bump the history
    # result_obj from fetch_site_status.run()
    def save_history_text(self, watch_uuid, contents):
        import uuid

        output_path = "{}/{}".format(self.datastore_path, watch_uuid)
        # Incase the operator deleted it, check and create.
        if not os.path.isdir(output_path):
            mkdir(output_path)

        fname = "{}/{}.stripped.txt".format(output_path, uuid.uuid4())
        with open(fname, 'wb') as f:
            f.write(contents)
            f.close()

        return fname

    def sync_to_json(self):
        logging.info("Saving JSON..")

        try:
            data = deepcopy(self.__data)
        except RuntimeError as e:
            # Try again in 15 seconds
            time.sleep(15)
            logging.error ("! Data changed when writing to JSON, trying again.. %s", str(e))
            self.sync_to_json()
            return
        else:

            try:
                # Re #286  - First write to a temp file, then confirm it looks OK and rename it
                # This is a fairly basic strategy to deal with the case that the file is corrupted,
                # system was out of memory, out of RAM etc
                with open(self.json_store_path+".tmp", 'w') as json_file:
                    json.dump(data, json_file, indent=4)
                os.rename(self.json_store_path+".tmp", self.json_store_path)
            except Exception as e:
                logging.error("Error writing JSON!! (Main JSON file save was skipped) : %s", str(e))

            self.needs_write = False

    # Thread runner, this helps with thread/write issues when there are many operations that want to update the JSON
    # by just running periodically in one thread, according to python, dict updates are threadsafe.
    def save_datastore(self):

        while True:
            if self.stop_thread:
                print("Shutting down datastore thread")
                return

            if self.needs_write:
                self.sync_to_json()

            # Once per minute is enough, more and it can cause high CPU usage
            # better here is to use something like self.app.config.exit.wait(1), but we cant get to 'app' from here
            for i in range(30):
                time.sleep(2)
                if self.stop_thread:
                    break

    # Go through the datastore path and remove any snapshots that are not mentioned in the index
    # This usually is not used, but can be handy.
    def remove_unused_snapshots(self):
        print ("Removing snapshots from datastore that are not in the index..")

        index=[]
        for uuid in self.data['watching']:
            for id in self.data['watching'][uuid]['history']:
                index.append(self.data['watching'][uuid]['history'][str(id)])

        import pathlib
        # Only in the sub-directories
        for item in pathlib.Path(self.datastore_path).rglob("*/*txt"):
            if not str(item) in index:
                print ("Removing",item)
                unlink(item)
