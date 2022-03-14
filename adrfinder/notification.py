import apprise
from apprise import NotifyFormat

valid_tokens = {
    'base_url': '',
    'restaurant': '',
    'watch_uuid': '',
    'watch_tag': '',
    'search_date': '',
    'search_time': '',
    'found_reservations': '',
    'party_size': ''
}

valid_notification_formats = {
    'Text': NotifyFormat.TEXT,
    'Markdown': NotifyFormat.MARKDOWN,
    'HTML': NotifyFormat.HTML,
}

default_notification_format = 'Text'
default_notification_body = 'Reservation found!\n---\nRestaurant: {restaurant}\nDate: {search_date}\nSearch Time: {search_time}\nParty Size: {party_size}\n---\n{found_reservations}\n---'
default_notification_title = 'ADRFinder Notification - {restaurant} / {search_date}'

def process_notification(n_object, datastore):

    apobj = apprise.Apprise(debug=True)

    print(">> Processing notification")

    for url in n_object['notification_urls']:
        url = url.strip()
        print (">> Process Notification: AppRise notifying {}".format(url))
        apobj.add(url)

    # Get the notification body from datastore
    n_body = n_object.get('notification_body', default_notification_body)
    n_title = n_object.get('notification_title', default_notification_title)
    n_format = valid_notification_formats.get(
        n_object['notification_format'],
        valid_notification_formats[default_notification_format],
    )


    # Insert variables into the notification content
    notification_parameters = create_notification_parameters(n_object, datastore)

    for n_k in notification_parameters:
        token = '{' + n_k + '}'
        val = notification_parameters[n_k]
        n_title = n_title.replace(token, val)
        n_body = n_body.replace(token, val)

    # https://github.com/caronc/apprise/wiki/Development_LogCapture
    # Anything higher than or equal to WARNING (which covers things like Connection errors)
    # raise it as an exception

    with apprise.LogCapture(level=apprise.logging.DEBUG) as logs:
        apobj.notify(
        body=n_body,
        title=n_title,
        body_format=n_format)

        # Returns empty string if nothing found, multi-line string otherwise
        log_value = logs.getvalue()
        if log_value and 'WARNING' in log_value or 'ERROR' in log_value:
            raise Exception(log_value)



# Notification title + body content parameters get created here.
def create_notification_parameters(n_object, datastore):
    from copy import deepcopy

    # in the case we send a test notification from the main settings, there is no UUID.
    uuid = n_object['uuid'] if 'uuid' in n_object else ''

    if uuid != '':
        watch_tag = datastore.data['watching'][uuid]['tag']
    else:
        watch_tag = ''

    # Create URLs to customise the notification with
    base_url = datastore.data['settings']['application']['base_url']

    # Re #148 - Some people have just {base_url} in the body or title, but this may break some notification services
    #           like 'Join', so it's always best to atleast set something obvious so that they are not broken.
    if base_url == '':
        base_url = "<base-url-env-var-not-set>"


    # Not sure deepcopy is needed here, but why not
    tokens = deepcopy(valid_tokens)


    # Valid_tokens also used as a field validator
    tokens.update(
        {
            'base_url': base_url if base_url is not None else '',
            'watch_uuid': uuid,
            'restaurant': n_object['restaurant'],
            'found_reservations': n_object['found_reservations'],
            'search_time': n_object['search_time'],
            'party_size': n_object['party_size'],
            'search_date': n_object['search_date'],
            'watch_tag': watch_tag if watch_tag is not None else '',
        })

    return tokens
