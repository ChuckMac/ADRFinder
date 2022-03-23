#!/usr/bin/python3


# @todo logging
# @todo extra options for url like , verify=False etc.
# @todo option for interval day/6 hour/etc
# @todo on change detected, config for calling some API
# @todo fetch title into json
# https://distill.io/features
# proxy per check
#  - flask_cors, itsdangerous,MarkupSafe

import datetime
import os
import queue
import threading
import time
from copy import deepcopy
from threading import Event

import flask_login
import pytz
import timeago
from feedgen.feed import FeedGenerator
from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import login_required
from adrfinder.restaurants import Restaurants

__version__ = '0.1.1'

datastore = None

# Local
running_update_threads = []
ticker_thread = None

extra_stylesheets = []

update_q = queue.Queue()

notification_q = queue.Queue()

# Needs to be set this way because we also build and publish via pip
base_path = os.path.dirname(os.path.realpath(__file__))
app = Flask(__name__,
            static_url_path="{}/static".format(base_path),
            template_folder="{}/templates".format(base_path))

# Stop browser caching of assets
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

app.config.exit = Event()

app.config['NEW_VERSION_AVAILABLE'] = False

app.config['LOGIN_DISABLED'] = False

# Disables caching of the templates
app.config['TEMPLATES_AUTO_RELOAD'] = True


notification_debug_log = []


def init_app_secret(datastore_path):
    secret = ""

    path = "{}/secret.txt".format(datastore_path)

    try:
        with open(path, "r") as f:
            secret = f.read()

    except FileNotFoundError:
        import secrets
        with open(path, "w") as f:
            secret = secrets.token_hex(32)
            f.write(secret)

    return secret


# Remember python is by reference
# populate_form in wtfors didnt work for me. (try using a setattr() obj 
# type on datastore.watch?)
def populate_form_from_watch(form, watch):
    for i in form.__dict__.keys():
        if i[0] != '_':
            p = getattr(form, i)
            if hasattr(p, 'data') and i in watch:
                setattr(p, "data", watch[i])


# We use the whole watch object from the store/JSON so we can see if there's 
# some related status in terms of a thread running or something similar.
@app.template_filter('format_last_checked_time')
def _jinja2_filter_datetime(watch_obj, format="%Y-%m-%d %H:%M:%S"):
    # Worker thread tells us which UUID it is currently processing.
    for t in running_update_threads:
        if t.current_uuid == watch_obj['uuid']:
            return "Checking now.."

    if watch_obj['last_checked'] == 0:
        return 'Not yet'

    return timeago.format(int(watch_obj['last_checked']), time.time())


# @app.context_processor
# def timeago():
#    def _timeago(lower_time, now):
#        return timeago.format(lower_time, now)
#    return dict(timeago=_timeago)

@app.template_filter('format_timestamp_timeago')
def _jinja2_filter_datetimestamp(timestamp, format="%Y-%m-%d %H:%M:%S"):
    return timeago.format(timestamp, time.time())
    # return timeago.format(timestamp, time.time())
    # return datetime.datetime.utcfromtimestamp(timestamp).strftime(format)


class User(flask_login.UserMixin):
    id = None

    def set_password(self, password):
        return True

    def get_user(self, email="defaultuser@adrfinder.com"):
        return self

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    # Compare given password against JSON store or Env var
    def check_password(self, password):

        import base64
        import hashlib

        # Can be stored in env (for deployments) or in the general configs
        raw_salt_pass = os.getenv("SALTED_PASS", False)

        if not raw_salt_pass:
            raw_salt_pass = datastore.data['settings']['application']['password']

        raw_salt_pass = base64.b64decode(raw_salt_pass)

        salt_from_storage = raw_salt_pass[:32]  # 32 is the length of the salt

        # Use the exact same setup you used to generate the key, but 
        # this time put in the password to check
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            salt_from_storage,
            100000
        )
        new_key = salt_from_storage + new_key

        return new_key == raw_salt_pass

    pass


def adrfinder_app(config=None, datastore_o=None):
    global datastore
    datastore = datastore_o

    login_manager = flask_login.LoginManager(app)
    login_manager.login_view = 'login'
    app.secret_key = init_app_secret(config['datastore_path'])

    # Setup cors headers to allow all domains
    # https://flask-cors.readthedocs.io/en/latest/
    #    CORS(app)

    @login_manager.user_loader
    def user_loader(email):
        user = User()
        user.get_user(email)
        return user

    @login_manager.unauthorized_handler
    def unauthorized_handler():
        # @todo validate its a URL of this host and use that
        return redirect(url_for('login', next=url_for('index')))

    @app.route('/logout')
    def logout():
        flask_login.logout_user()
        return redirect(url_for('index'))

    # https://github.com/pallets/flask/blob/93dd1709d05a1cf0e886df6223377bdab3b077fb/examples/tutorial/flaskr/__init__.py#L39
    # You can divide up the stuff like this
    @app.route('/login', methods=['GET', 'POST'])
    def login():

        if not datastore.data['settings']['application']['password'] and not os.getenv("SALTED_PASS", False):
            flash("Login not required, no password enabled.", "notice")
            return redirect(url_for('index'))

        if request.method == 'GET':
            output = render_template("login.html")
            return output

        user = User()
        user.id = "defaultuser@adrfinder.com"

        password = request.form.get('password')

        if (user.check_password(password)):
            flask_login.login_user(user, remember=True)

            # For now there's nothing else interesting here other than the index/list page
            # It's more reliable and safe to ignore the 'next' redirect
            # When we used...
            # next = request.args.get('next')
            # return redirect(next or url_for('index'))
            # We would sometimes get login loop errors on sites hosted in sub-paths

            # note for the future:
            #            if not is_safe_url(next):
            #                return flask.abort(400)
            return redirect(url_for('index'))

        else:
            flash('Incorrect password', 'error')

        return redirect(url_for('login'))

    @app.before_request
    def do_something_whenever_a_request_comes_in():

        # Disable password login if there is not one set
        # (No password in settings or env var)
        app.config['LOGIN_DISABLED'] = datastore.data['settings']['application']['password'] == False and os.getenv("SALTED_PASS", False) == False

        # For the RSS path, allow access via a token
        if request.path == '/rss' and request.args.get('token'):
            app_rss_token = datastore.data['settings']['application']['rss_access_token']
            rss_url_token = request.args.get('token')
            if app_rss_token == rss_url_token:
                app.config['LOGIN_DISABLED'] = True

    @app.route("/rss", methods=['GET'])
    @login_required
    def rss():

        limit_tag = request.args.get('tag')

        # Sort by last_changed and add the uuid which is usually the key..
        sorted_watches = []

        # @todo needs a .itemsWithTag() or something
        for uuid, watch in datastore.data['watching'].items():

            if limit_tag != None:
                # Support for comma separated list of tags.
                for tag_in_watch in watch['tag'].split(','):
                    tag_in_watch = tag_in_watch.strip()
                    if tag_in_watch == limit_tag:
                        watch['uuid'] = uuid
                        sorted_watches.append(watch)

            else:
                watch['uuid'] = uuid
                sorted_watches.append(watch)

        sorted_watches.sort(key=lambda x: x['last_changed'], reverse=True)

        fg = FeedGenerator()
        fg.title('ADR Finder')
        fg.description('Feed description')
        fg.link(href='https://github.com/chuckmac/adrfinder')

        for watch in sorted_watches:
            if not watch['viewed']:
                # Re #239 - GUID needs to be individual for each event
                guid = "{}/{}".format(watch['uuid'], watch['last_changed'])
                fe = fg.add_entry()

                # Include a link to the diff page, they will have to login here to see if password protection is enabled.
                # Description is the page you watch, link takes you to the diff JS UI page
                base_url = datastore.data['settings']['application']['base_url']
                if base_url == '':
                    base_url = "<base-url-env-var-not-set>"

                hist_link = {'href': "{}{}".format(base_url, url_for('history_page', uuid=watch['uuid']))}

                rest_and_times = get_restaurants_and_times()
                # @todo use title if it exists
                fe.link(link=hist_link)
                title = rest_and_times['restaurants'][watch['restaurant']] + " - " + datetime.datetime.strptime(watch['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y') + " - " + rest_and_times['search_times'][watch['search_time']]
                fe.title(title=title)


                # @todo in the future <description><![CDATA[<html><body>Any code html is valid.</body></html>]]></description>
                fe.description(description=title)

                fe.guid(guid, permalink=False)
                dt = datetime.datetime.fromtimestamp(int(watch['newest_history_key']))
                dt = dt.replace(tzinfo=pytz.UTC)
                fe.pubDate(dt)

        response = make_response(fg.rss_str())
        response.headers.set('Content-Type', 'application/rss+xml')
        return response

    @app.route("/", methods=['GET'])
    @login_required
    def index():
        limit_tag = request.args.get('tag')
        pause_uuid = request.args.get('pause')

        # Redirect for the old rss path which used the /?rss=true
        if request.args.get('rss'):
            return redirect(url_for('rss', tag=limit_tag))

        if pause_uuid:
            try:
                datastore.data['watching'][pause_uuid]['paused'] ^= True
                datastore.needs_write = True

                return redirect(url_for('index', tag = limit_tag))
            except KeyError:
                pass

        # Sort by last_changed and add the uuid which is usually the key..
        sorted_watches = []
        expired_watches = []
        rest_and_times = get_restaurants_and_times()
        for uuid, watch in datastore.data['watching'].items():

            watch['restaurant_name'] = rest_and_times['restaurants'][watch['restaurant']]
            watch['search_time_formatted'] = rest_and_times['search_times'][watch['search_time']]
            watch['date_formatted']  = datetime.datetime.strptime(watch['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y')

            watch['expired'] = False
            if watch['date'] < datetime.datetime.today().strftime('%Y-%m-%d'):
                watch['expired'] = True

            if watch['paused'] == True and watch['paused_until']:
                timediff = watch['paused_until'] - int(datetime.datetime.now().timestamp())
                if timediff >= 3600:
                    watch['paused_for'] = "{} hours".format(int(timediff/3600))
                else:
                    watch['paused_for'] = "{} minutes".format(int(timediff/60))

            if limit_tag != None:
                # Support for comma separated list of tags.
                for tag_in_watch in watch['tag'].split(','):
                    tag_in_watch = tag_in_watch.strip()
                    if tag_in_watch == limit_tag:
                        watch['uuid'] = uuid
                        if watch['expired'] is True:
                            expired_watches.append(watch)
                        else:
                            sorted_watches.append(watch)

            else:
                watch['uuid'] = uuid
                if watch['expired'] is True:
                    expired_watches.append(watch)
                else:
                    sorted_watches.append(watch)

        sorted_watches.extend(expired_watches)

        existing_tags = datastore.get_all_tags()

        from adrfinder import forms
        form = forms.quickWatchForm(request.form)

        output = render_template("watch-overview.html",
                                 form=form,
                                 watches=sorted_watches,
                                 tags=existing_tags,
                                 active_tag=limit_tag,
                                 app_rss_token=datastore.data['settings']['application']['rss_access_token'],
                                 has_unviewed=datastore.data['has_unviewed'],
                                 # Don't link to hosting when we're on the hosting environment
                                 hosted_sticky=os.getenv("SALTED_PASS", False) == False,
                                 guid=datastore.data['app_guid'])

        return output


    @app.route("/edit/<string:uuid>", methods=['GET', 'POST'])
    @login_required
    def edit_page(uuid):
        from adrfinder import forms
        form = forms.watchForm(request.form)

        # More for testing, possible to return the first/only
        if uuid == 'first':
            uuid = list(datastore.data['watching'].keys()).pop()


        if request.method == 'GET':
            if not uuid in datastore.data['watching']:
                flash("No watch with the UUID %s found." % (uuid), "error")
                return redirect(url_for('index'))

            populate_form_from_watch(form, datastore.data['watching'][uuid])


        if request.method == 'POST' and form.validate():

            # Re #110, if they submit the same as the default value, set it to None, so we continue to follow the default
            if form.minutes_between_check.data == datastore.data['settings']['requests']['minutes_between_check']:
                form.minutes_between_check.data = None

            update_obj = {'restaurant': form.restaurant.data.strip(),
                          'date': form.date.data.strftime('%Y-%m-%d'),
                          'party_size': form.party_size.data.strip(),
                          'search_time': form.search_time.data.strip(),
                          'minutes_between_check': form.minutes_between_check.data,
                          'tag': form.tag.data.strip(),
                          'title': form.title.data.strip(),
                          'notification_title': form.notification_title.data,
                          'notification_body': form.notification_body.data,
                          'notification_format': form.notification_format.data,
                          }

            # Notification URLs
            datastore.data['watching'][uuid]['notification_urls'] = form.notification_urls.data

            datastore.data['watching'][uuid].update(update_obj)

            flash("Updated watch.")

            # Re #286 - We wait for syncing new data to disk in another thread every 60 seconds
            # But in the case something is added we should save straight away
            datastore.sync_to_json()

            # Queue the watch for immediate recheck
            update_q.put(uuid)

            if form.trigger_check.data:
                if len(form.notification_urls.data):
                    n_object = {'restaurant': form.restaurant.data.strip(),
                                'date': form.date.data,
                                'party_size': form.party_size.data.strip(),
                                'search_time': form.search_time.data.strip(),
                                'found_reservations': "ZZ:00 AM - https://disneyworld.disney.go.com/",
                                'notification_urls': form.notification_urls.data,
                                'notification_title': form.notification_title.data,
                                'notification_body': form.notification_body.data,
                                'notification_format': form.notification_format.data,
                                'uuid': uuid
                                }
                    notification_q.put(n_object)
                    flash('Test notification queued.')
                else:
                    flash('No notification URLs set, cannot send test.', 'error')

            if form.save_and_preview_button.data:
                flash('You may need to reload this page to see the new content.')
                return redirect(url_for('preview_page', uuid=uuid))
            else:
                return redirect(url_for('index'))

        else:
            if request.method == 'POST' and not form.validate():
                flash("An error occurred, please see below.", "error")

            # Re #110 offer the default minutes
            using_default_minutes = False
            if form.minutes_between_check.data == None:
                form.minutes_between_check.data = datastore.data['settings']['requests']['minutes_between_check']
                using_default_minutes = True

            # Re #110 offer the default pause
            using_default_pause = False
            if form.pause_length.data == None:
                form.pause_length.data = datastore.data['settings']['application']['pause_length']
                using_default_pause = True

            if not isinstance(form.date.data, datetime.datetime) and not isinstance(form.date.data, datetime.date):
                form.date.data = datetime.datetime.strptime(form.date.data, '%Y-%m-%d')

            output = render_template("edit.html",
                                     uuid=uuid,
                                     watch=datastore.data['watching'][uuid],
                                     form=form,
                                     using_default_minutes=using_default_minutes,
                                     using_default_pause=using_default_pause,
                                     current_base_url = datastore.data['settings']['application']['base_url']
                                     )

        return output

    @app.route("/settings", methods=['GET', "POST"])
    @login_required
    def settings_page():

        from adrfinder import forms

        form = forms.globalSettingsForm(request.form)

        if request.method == 'GET':
            form.minutes_between_check.data = int(datastore.data['settings']['requests']['minutes_between_check'])
            form.pause_length.data = datastore.data['settings']['application']['pause_length']
            form.notification_urls.data = datastore.data['settings']['application']['notification_urls']
            form.notification_title.data = datastore.data['settings']['application']['notification_title']
            form.notification_body.data = datastore.data['settings']['application']['notification_body']
            form.notification_format.data = datastore.data['settings']['application']['notification_format']
            form.base_url.data = datastore.data['settings']['application']['base_url']

            # Password unset is a GET, but we can lock the session to always need the password
            if not os.getenv("SALTED_PASS", False) and request.values.get('removepassword') == 'yes':
                from pathlib import Path
                datastore.data['settings']['application']['password'] = False
                flash("Password protection removed.", 'notice')
                flask_login.logout_user()
                return redirect(url_for('settings_page'))

        if request.method == 'POST' and form.validate():

            datastore.data['settings']['application']['notification_urls'] = form.notification_urls.data
            datastore.data['settings']['requests']['minutes_between_check'] = form.minutes_between_check.data
            datastore.data['settings']['application']['pause_length'] = form.pause_length.data
            datastore.data['settings']['application']['notification_title'] = form.notification_title.data
            datastore.data['settings']['application']['notification_body'] = form.notification_body.data
            datastore.data['settings']['application']['notification_format'] = form.notification_format.data
            datastore.data['settings']['application']['notification_urls'] = form.notification_urls.data
            datastore.data['settings']['application']['base_url'] = form.base_url.data

            if form.trigger_check.data:
                if len(form.notification_urls.data):
                    n_object = {'restaurant': "Test from ADR Finder",
                                'search_date': "1/1/1970",
                                'party_size': "1",
                                'search_time': "Lunch",
                                'found_reservations': "11:00 AM - https://disneyworld.disney.go.com/",
                                'notification_urls': form.notification_urls.data,
                                'notification_title': form.notification_title.data,
                                'notification_body': form.notification_body.data,
                                'notification_format': form.notification_format.data,
                                }
                    notification_q.put(n_object)
                    flash('Test notification queued.')
                else:
                    flash('No notification URLs set, cannot send test.', 'error')

            if not os.getenv("SALTED_PASS", False) and form.password.encrypted_password:
                datastore.data['settings']['application']['password'] = form.password.encrypted_password
                flash("Password protection enabled.", 'notice')
                flask_login.logout_user()
                return redirect(url_for('index'))

            datastore.needs_write = True
            flash("Settings updated.")

        if request.method == 'POST' and not form.validate():
            flash("An error occurred, please see below.", "error")

        output = render_template("settings.html",
                                 form=form,
                                 current_base_url = datastore.data['settings']['application']['base_url'],
                                 hide_remove_pass=os.getenv("SALTED_PASS", False))

        return output

    @app.route("/import", methods=['GET', "POST"])
    @login_required
    def import_page():
        import json

        if request.method == 'POST':

            if 'importfile' not in request.files:
                flash("Error: No File Uploaded")
                output = render_template("import.html")
                return output

            upload_file = request.files['importfile']
            upload_file.seek(0)
            file_contents = upload_file.read()

            try:
                data = json.loads(file_contents)
            except ValueError as e:
                flash("Error: File contains invalid JSON. {}".format(e))
                output = render_template("import.html")
                return output

            if 'watching' not in data:
                flash("Error: No restaurant watches found in file")
                output = render_template("import.html")
                return output

            # Import as new watch but save existing data
            added = 0
            for uuid, watch in data['watching'].items():
                new_uuid = datastore.add_watch(
                    restaurant=watch['restaurant'],
                    date=watch['date'],
                    party_size=watch['party_size'],
                    search_time=watch['search_time'],
                    tag=watch['tag'],
                    extras=watch
                )
                added += 1

            flash("{} restaurant watches added.".format(added))

            setting = request.values.get('setting')
            if 'all_settings' == setting:
                datastore.settings = data['settings']
                datastore.needs_write = True
                flash("Settings have been updated")

        # Could be some remaining, or we could be on GET
        output = render_template("import.html",
                                 remaining=""
                                 )
        return output

    # Clear all statuses, so we do not see the 'unviewed' class
    @app.route("/api/mark-all-viewed", methods=['GET'])
    @login_required
    def mark_all_viewed():

        # Save the current newest history as the most recently viewed
        for watch_uuid, watch in datastore.data['watching'].items():
            datastore.set_last_viewed(watch_uuid, watch['newest_history_key'])

        flash("Cleared all statuses.")
        return redirect(url_for('index'))

    @app.route("/history/<string:uuid>", methods=['GET'])
    @login_required
    def history_page(uuid):
        try:
            watch = datastore.data['watching'][uuid]
        except KeyError:
            flash("No history found for the specified link, bad link?", "error")
            return redirect(url_for('index'))

        rest_and_times = get_restaurants_and_times()

        total_matches = 0
        history = []
        for event in watch['history']:
            for offer in watch['history'][event]:
                if 'time' in offer:
                    total_matches += 1
                    date = datetime.datetime.fromtimestamp(int(str(event))).strftime('%Y-%m-%d %I:%M %p')
                    history.append({'date': date, 'time': offer['time'], 'url': offer['url']})

        output = render_template("history.html", watch_a=watch,
                                 uuid=uuid,
                                 history=history,
                                 total_searches=watch['total_searches'],
                                 total_matches=total_matches,
                                 restaurant=rest_and_times['restaurants'][watch['restaurant']],
                                 search_time=rest_and_times['search_times'][watch['search_time']],
                                 date=datetime.datetime.strptime(watch['date'], '%Y-%m-%d').date().strftime('%m/%d/%Y'),
                                 left_sticky=False)

        return output


    @app.route("/settings/notification-logs", methods=['GET'])
    @login_required
    def notification_logs():
        global notification_debug_log
        output = render_template("notification-log.html",
                                 logs=notification_debug_log if len(notification_debug_log) else ["No errors or warnings detected"])

        return output
    @app.route("/api/<string:uuid>/snapshot/current", methods=['GET'])
    @login_required
    def api_snapshot(uuid):

        # More for testing, possible to return the first/only
        if uuid == 'first':
            uuid = list(datastore.data['watching'].keys()).pop()

        try:
            watch = datastore.data['watching'][uuid]
        except KeyError:
            return abort(400, "No history found for the specified link, bad link?")

        newest = list(watch['history'].keys())[-1]
        with open(watch['history'][newest], 'r') as f:
            content = f.read()

        resp = make_response(content)
        resp.headers['Content-Type'] = 'text/plain'
        return resp

    @app.route("/favicon.ico", methods=['GET'])
    def favicon():
        return send_from_directory("static/images", path="favicon.ico")

    # We're good but backups are even better!
    @app.route("/backup", methods=['GET'])
    @login_required
    def get_backup():

        import zipfile
        from pathlib import Path

        # Remove any existing backup file, for now we just keep one file

        for previous_backup_filename in Path(datastore_o.datastore_path).rglob('adrfinder-backup-*.zip'):
            os.unlink(previous_backup_filename)

        # create a ZipFile object
        backupname = "adrfinder-backup-{}.zip".format(int(time.time()))

        # We only care about UUIDS from the current index file
        uuids = list(datastore.data['watching'].keys())
        backup_filepath = os.path.join(datastore_o.datastore_path, backupname)

        with zipfile.ZipFile(backup_filepath, "w",
                             compression=zipfile.ZIP_DEFLATED,
                             compresslevel=8) as zipObj:

            # Be sure we're written fresh
            datastore.sync_to_json()

            # Add the index
            zipObj.write(os.path.join(datastore_o.datastore_path, "restaurant-watches.json"), arcname="restaurant-watches.json")

            # Add the flask app secret
            zipObj.write(os.path.join(datastore_o.datastore_path, "secret.txt"), arcname="secret.txt")

            # Add any snapshot data we find, use the full path to access the file, but make the file 'relative' in the Zip.
            for txt_file_path in Path(datastore_o.datastore_path).rglob('*.txt'):
                parent_p = txt_file_path.parent
                if parent_p.name in uuids:
                    zipObj.write(txt_file_path,
                                 arcname=str(txt_file_path).replace(datastore_o.datastore_path, ''),
                                 compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=8)

        # Send_from_directory needs to be the full absolute path
        return send_from_directory(os.path.abspath(datastore_o.datastore_path), backupname, as_attachment=True)

    @app.route("/static/<string:group>/<string:filename>", methods=['GET'])
    def static_content(group, filename):
        # These files should be in our subdirectory
        try:
            return send_from_directory("static/{}".format(group), path=filename)
        except FileNotFoundError:
            abort(404)

    @app.route("/api/add", methods=['POST'])
    @login_required
    def api_watch_add():
        from adrfinder import forms
        form = forms.quickWatchForm(request.form, [])

        if form.validate():

            restaurant = request.form.get('restaurant').strip()
            date = request.form.get('date').strip()
            party_size = request.form.get('party_size').strip()
            search_time = request.form.get('search_time').strip()

            if datastore.watch_exists(restaurant, date, party_size, search_time):
                flash('The alert {} already exists'.format(restaurant), "error")
                return redirect(url_for('index'))

            # @todo add_watch should throw a custom Exception for validation etc
            new_uuid = datastore.add_watch(restaurant=restaurant, date=date, party_size=party_size, search_time=search_time, tag=request.form.get('tag').strip())
            # Straight into the queue.
            update_q.put(new_uuid)

            flash("Watch added.")
            return redirect(url_for('index'))
        else:
            flash("Error")
            return redirect(url_for('index'))

    @app.route("/api/delete", methods=['GET'])
    @login_required
    def api_delete():
        uuid = request.args.get('uuid')
        datastore.delete(uuid)
        flash('Deleted.')

        return redirect(url_for('index'))

    @app.route("/api/clone", methods=['GET'])
    @login_required
    def api_clone():
        uuid = request.args.get('uuid')
        # More for testing, possible to return the first/only
        if uuid == 'first':
            uuid = list(datastore.data['watching'].keys()).pop()

        new_uuid = datastore.clone(uuid)
        update_q.put(new_uuid)
        flash('Cloned.')

        return redirect(url_for('index'))

    @app.route("/api/checknow", methods=['GET'])
    @login_required
    def api_watch_checknow():

        tag = request.args.get('tag')
        uuid = request.args.get('uuid')
        i = 0

        running_uuids = []
        for t in running_update_threads:
            running_uuids.append(t.current_uuid)

        # @todo check thread is running and skip

        if uuid:
            if uuid not in running_uuids:
                update_q.put(uuid)
            i = 1

        elif tag != None:
            # Items that have this current tag
            for watch_uuid, watch in datastore.data['watching'].items():
                if (tag != None and tag in watch['tag']):
                    if watch_uuid not in running_uuids and not datastore.data['watching'][watch_uuid]['paused']:
                        update_q.put(watch_uuid)
                        i += 1

        else:
            # No tag, no uuid, add everything.
            for watch_uuid, watch in datastore.data['watching'].items():

                if watch_uuid not in running_uuids and not datastore.data['watching'][watch_uuid]['paused']:
                    update_q.put(watch_uuid)
                    i += 1
        flash("{} watches are queued for rechecking.".format(i))
        return redirect(url_for('index', tag=tag))

    # @todo handle ctrl break
    ticker_thread = threading.Thread(target=ticker_thread_check_time_launch_checks).start()

    threading.Thread(target=notification_runner).start()

    # Check for new release version, but not when running in test/build
    if not os.getenv("GITHUB_REF", False):
        threading.Thread(target=check_for_new_version).start()

    return app


# Check for new version and anonymous stats
def check_for_new_version():
    import requests
    import urllib3
    import adrfinder
    import json
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    while not app.config.exit.is_set():
        try:
            r = requests.get('https://api.github.com/repos/chuckmac/adrfinder/releases/latest', verify=False)
        except:
            pass

        try:
            gh_json = json.loads(r.content)
        except:
            pass

        try: # If we have a new version, show it
            if gh_json['tag_name'] != adrfinder.__version__:
                #flash("New version available: {}".format(json['tag_name']))
                app.config['NEW_VERSION_AVAILABLE'] = True
        except:
            pass

        # Check daily
        app.config.exit.wait(86400)

def notification_runner():
    global notification_debug_log
    while not app.config.exit.is_set():
        try:
            # At the moment only one thread runs (single runner)
            n_object = notification_q.get(block=False)
        except queue.Empty:
            time.sleep(1)

        else:
            # Process notifications
            try:
                from adrfinder import notification
                notification.process_notification(n_object, datastore)

            except Exception as e:
                print("Restaurant: {}  Error {}".format(n_object['restaurant'], str(e)))

                # UUID wont be present when we submit a 'test' from the global settings
                if 'uuid' in n_object:
                    datastore.update_watch(uuid=n_object['uuid'],
                                           update_obj={'last_notification_error': "Notification error detected, please see logs."})

                log_lines = str(e).splitlines()
                notification_debug_log += log_lines

                # Trim the log length
                notification_debug_log = notification_debug_log[-100:]




# Thread runner to check every minute, look for new watches to feed into the Queue.
def ticker_thread_check_time_launch_checks():
    from adrfinder import update_worker

    # Spin up Workers that do the fetching
    # Can be overriden by ENV or use the default settings
    n_workers = int(os.getenv("FETCH_WORKERS", datastore.data['settings']['requests']['workers']))
    for _ in range(n_workers):
        new_worker = update_worker.update_worker(update_q, notification_q, app, datastore)
        running_update_threads.append(new_worker)
        new_worker.start()

    while not app.config.exit.is_set():

        # Get a list of watches by UUID that are currently fetching data
        running_uuids = []
        for t in running_update_threads:
            if t.current_uuid:
                running_uuids.append(t.current_uuid)

        # Re #232 - Deepcopy the data incase it changes while we're iterating through it all
        while True:
            try:
                copied_datastore = deepcopy(datastore)
            except RuntimeError as e:
                # RuntimeError: dictionary changed size during iteration
                time.sleep(0.1)
            else:
                break

        # Re #438 - Don't place more watches in the queue to be checked if the queue is already large
        while update_q.qsize() >= 2000:
            time.sleep(1)

        # Check for watches outside of the time threshold to put in the thread queue.
        now = time.time()
        max_system_wide = int(copied_datastore.data['settings']['requests']['minutes_between_check']) * 60

        for uuid, watch in copied_datastore.data['watching'].items():

            # Check if watch is expired
            if watch['date'] < datetime.datetime.today().strftime('%Y-%m-%d'):
                continue

            # Check if we need to unpause
            if watch['paused'] and watch['paused_until']:
                if watch['paused_until'] <= int(now):
                    watch['paused'] = False
                    datastore.update_watch(uuid=watch['uuid'],
                                           data={'paused': False, "paused_until": None})

            # No need todo further processing if it's paused
            if watch['paused']:
                continue

            # If they supplied an individual entry minutes to threshold.
            watch_minutes_between_check = watch.get('minutes_between_check', None)
            if watch_minutes_between_check is not None:
                # Cast to int just incase
                max_time = int(watch_minutes_between_check) * 60
            else:
                # Default system wide.
                max_time = max_system_wide

            threshold = now - max_time

            # Yeah, put it in the queue, it's more than time
            if watch['last_checked'] <= threshold:
                if not uuid in running_uuids and uuid not in update_q.queue:
                    update_q.put(uuid)

        # Wait a few seconds before checking the list again
        time.sleep(3)

        # Should be low so we can break this out in testing
        app.config.exit.wait(1)


def get_restaurants_and_times():

    rest_refresh = datastore.data['settings']['requests']['minutes_before_restaurant_refresh']
    rest_last_updated = datastore.data['cache']['restaurants']['last_updated']
    if type(rest_last_updated) != int:
        rest_last_updated = 0
    refresh_time = int(rest_last_updated) + (int(rest_refresh) * 60)

    if rest_last_updated == '' or refresh_time <= int(time.time()):
        rest = Restaurants()
        restaurants = rest.get_restaurants()
        search_times = rest.get_search_times()
        rest_and_times = {'restaurants': restaurants, 'search_times': search_times}

        datastore.data['cache']['restaurants']['data'] = restaurants
        datastore.data['cache']['restaurants']['times'] = search_times
        datastore.data['cache']['restaurants']['last_updated'] = int(time.time())
        datastore.needs_write = True
    else:
        rest_and_times = {'restaurants': datastore.data['cache']['restaurants']['data'], 'search_times': datastore.data['cache']['restaurants']['times']}


    return rest_and_times
