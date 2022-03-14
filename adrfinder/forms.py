from wtforms import Form, SelectField, RadioField, BooleanField, StringField, PasswordField, validators, IntegerField, fields, TextAreaField, \
    Field

from wtforms import widgets, SubmitField
from wtforms.validators import ValidationError, InputRequired
from wtforms.fields import html5
from wtforms_components import DateRange
from adrfinder import content_fetcher, get_restaurants_and_times
import re
from datetime import datetime, timedelta
from markupsafe import Markup
from wtforms.widgets.core import html_params

from adrfinder.notification import default_notification_format, valid_notification_formats, default_notification_body, default_notification_title

default_method = 'GET'

class CustomSelect:
    """
    Renders a select field allowing custom attributes for options.
    Expects the field to be an iterable object of Option fields.
    The render function accepts a dictionary of option ids ("{field_id}-{option_index}")
    which contain a dictionary of attributes to be passed to the option.

    Example:
    form.customselect(option_attr={"customselect-0": {"disabled": ""} })
    """

    def __init__(self, multiple=False):
        self.multiple = multiple

    def __call__(self, field, option_attr=None, **kwargs):
        if option_attr is None:
            option_attr = {}
        kwargs.setdefault("id", field.id)
        if self.multiple:
            kwargs["multiple"] = True
        if "required" not in kwargs and "required" in getattr(field, "flags", []):
            kwargs["required"] = True
        html = ["<select %s>" % html_params(name=field.name, **kwargs)]
        for option in field:
            attr = option_attr.get(option.id, {})
            html.append(option(**attr))
        html.append("</select>")
        return Markup("".join(html))


class StringListField(StringField):
    widget = widgets.TextArea()

    def _value(self):
        if self.data:
            return "\r\n".join(self.data)
        else:
            return u''

    # incoming
    def process_formdata(self, valuelist):
        if valuelist:
            # Remove empty strings
            cleaned = list(filter(None, valuelist[0].split("\n")))
            self.data = [x.strip() for x in cleaned]
            p = 1
        else:
            self.data = []



class SaltyPasswordField(StringField):
    widget = widgets.PasswordInput()
    encrypted_password = ""

    def build_password(self, password):
        import hashlib
        import base64
        import secrets

        # Make a new salt on every new password and store it with the password
        salt = secrets.token_bytes(32)

        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        store = base64.b64encode(salt + key).decode('ascii')

        return store

    # incoming
    def process_formdata(self, valuelist):
        if valuelist:
            # Be really sure it's non-zero in length
            if len(valuelist[0].strip()) > 0:
                self.encrypted_password = self.build_password(valuelist[0])
                self.data = ""
        else:
            self.data = False


# Separated by  key:value
class StringDictKeyValue(StringField):
    widget = widgets.TextArea()

    def _value(self):
        if self.data:
            output = u''
            for k in self.data.keys():
                output += "{}: {}\r\n".format(k, self.data[k])

            return output
        else:
            return u''

    # incoming
    def process_formdata(self, valuelist):
        if valuelist:
            self.data = {}
            # Remove empty strings
            cleaned = list(filter(None, valuelist[0].split("\n")))
            for s in cleaned:
                parts = s.strip().split(':', 1)
                if len(parts) == 2:
                    self.data.update({parts[0].strip(): parts[1].strip()})

        else:
            self.data = {}

class ValidateContentFetcherIsReady(object):
    """
    Validates that anything that looks like a regex passes as a regex
    """
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        from adrfinder import content_fetcher
        import urllib3.exceptions

        # Better would be a radiohandler that keeps a reference to each class
        if field.data is not None:
            klass = getattr(content_fetcher, field.data)
            some_object = klass()
            try:
                ready = some_object.is_ready()

            except urllib3.exceptions.MaxRetryError as e:
                driver_url = some_object.command_executor
                message = field.gettext('Content fetcher \'%s\' did not respond.' % (field.data))
                message += '<br/>' + field.gettext(
                    'Be sure that the selenium/webdriver runner is running and accessible via network from this container/host.')
                message += '<br/>' + field.gettext('Did you follow the instructions in the wiki?')
                message += '<br/><br/>' + field.gettext('WebDriver Host: %s' % (driver_url))
                message += '<br/><a href="https://github.com/chuckmac/adrfinder/wiki/Fetching-pages-with-WebDriver">Go here for more information</a>'
                message += '<br/>'+field.gettext('Content fetcher did not respond properly, unable to use it.\n %s' % (str(e)))

                raise ValidationError(message)

            except Exception as e:
                message = field.gettext('Content fetcher \'%s\' did not respond properly, unable to use it.\n %s')
                raise ValidationError(message % (field.data, e))


class ValidateNotificationBodyAndTitleWhenURLisSet(object):
    """
       Validates that they entered something in both notification title+body when the URL is set
       Due to https://github.com/chuckmac/adrfinder/issues/360
       """

    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        if len(field.data):
            if not len(form.notification_title.data) or not len(form.notification_body.data):
                message = field.gettext('Notification Body and Title is required when a Notification URL is used')
                raise ValidationError(message)

class ValidateAppRiseServers(object):
    """
       Validates that each URL given is compatible with AppRise
       """

    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        import apprise
        apobj = apprise.Apprise()

        for server_url in field.data:
            if not apobj.add(server_url):
                message = field.gettext('\'%s\' is not a valid AppRise URL.' % (server_url))
                raise ValidationError(message)

class ValidateTokensList(object):
    """
    Validates that a {token} is from a valid set
    """
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        from adrfinder import notification
        regex = re.compile('{.*?}')
        for p in re.findall(regex, field.data):
            if not p.strip('{}') in notification.valid_tokens:
                message = field.gettext('Token \'%s\' is not a valid token.')
                raise ValidationError(message % (p))

class ValidateSelectOption(object):
    """
    Validates that a {token} is from a valid set
    """
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
         if field.data == "None":
            message = field.gettext('Please select a restaurant.')
            raise ValidationError(message)
class quickWatchForm(Form):
    # https://wtforms.readthedocs.io/en/2.3.x/fields/#module-wtforms.fields.html5
    # `require_tld` = False is needed even for the test harness "http://localhost:5005.." to run
    tag = StringField('Group tag', [validators.Optional(), validators.Length(max=35)])
    rest_and_times = get_restaurants_and_times()
    restaurants = rest_and_times['restaurants']
    
    choices = [(k, v) for k, v in rest_and_times['restaurants'].items()]
    choices.insert(0, ("None", "Select a restaurant"))

    restaurant = SelectField(u'Restaurant', choices=choices, validators=[InputRequired(), ValidateSelectOption()], widget=CustomSelect())
    date = html5.DateField(u'Date', render_kw={'min': datetime.today().strftime('%Y-%m-%d'), 'max': (datetime.today() + timedelta(days=90)).strftime('%Y-%m-%d')}, validators=[InputRequired(), DateRange(min=datetime.today().date(), max=(datetime.today().date() + timedelta(days=90)))])
    party_size = SelectField(u'Party Size', choices=[('1', '1 Person'), ('2', '2 People'), ('3', '3 People'), ('4', '4 People'), ('5', '5 People'), ('6', '6 People'), ('7', '7 People'), ('8', '8 People'), ('9', '9 People'), ('10', '10 People')], default="4",  validators=[InputRequired()])
    choices = [(k, v) for k, v in rest_and_times['search_times'].items()]
    search_time = SelectField(u'Search Time', choices=choices, validators=[InputRequired()])

class commonSettingsForm(Form):

    notification_urls = StringListField('Notification URL List', validators=[validators.Optional(), ValidateNotificationBodyAndTitleWhenURLisSet(), ValidateAppRiseServers()])
    notification_title = StringField('Notification Title', default=default_notification_title, validators=[validators.Optional(), ValidateTokensList()])
    notification_body = TextAreaField('Notification Body', default=default_notification_body, validators=[validators.Optional(), ValidateTokensList()])
    notification_format = SelectField('Notification Format', choices=valid_notification_formats.keys(), default=default_notification_format)
    trigger_check = BooleanField('Send test notification on save')

class watchForm(commonSettingsForm):

    tag = StringField('Group tag', [validators.Optional(), validators.Length(max=35)])
    rest_and_times = get_restaurants_and_times()
    restaurants = rest_and_times['restaurants']
    
    choices = [(k, v) for k, v in rest_and_times['restaurants'].items()]
    choices.insert(0, ("None", "Select a restaurant"))

    restaurant = SelectField(u'Restaurant', choices=choices, validators=[InputRequired(), ValidateSelectOption()], widget=CustomSelect())
    date = html5.DateField(u'Date', render_kw={'min': datetime.today().strftime('%Y-%m-%d'), 'max': (datetime.today() + timedelta(days=90)).strftime('%Y-%m-%d')}, validators=[InputRequired(), DateRange(min=datetime.today().date(), max=(datetime.today().date() + timedelta(days=90)))])
    party_size = SelectField(u'Party Size', choices=[('1', '1 Person'), ('2', '2 People'), ('3', '3 People'), ('4', '4 People'), ('5', '5 People'), ('6', '6 People'), ('7', '7 People'), ('8', '8 People'), ('9', '9 People'), ('10', '10 People')], default="4",  validators=[InputRequired()])
    choices = [(k, v) for k, v in rest_and_times['search_times'].items()]
    search_time = SelectField(u'Search Time', choices=choices, validators=[InputRequired()])
    
    minutes_between_check = html5.IntegerField('Maximum time in minutes until recheck',
                                               [validators.Optional(), validators.NumberRange(min=1)])
    pause_length = SelectField('Pause After Notification', choices=[(0, 'Until Restarted'), ('15', '15 minutes'), ('30', '30 minutes'), ('60', '1 hour'), ('480', '8 hours'), ('1440', '1 day') ], validators=[validators.Optional()])
    title = StringField('Title')

    save_button = SubmitField('Save', render_kw={"class": "pure-button pure-button-primary"})
    save_and_preview_button = SubmitField('Save & Preview', render_kw={"class": "pure-button pure-button-primary"})

    def validate(self, **kwargs):
        if not super().validate():
            return False

        result = True

        return result

class globalSettingsForm(commonSettingsForm):

    password = SaltyPasswordField()
    minutes_between_check = html5.IntegerField('Maximum time in minutes until recheck',
                                               [validators.NumberRange(min=1)])
    base_url = StringField('Base URL', validators=[validators.Optional()])
    pause_length = SelectField(U'Pause After Notification', choices=[(0, 'Until Restarted'), ('15', '15 minutes'), ('30', '30 minutes'), ('60', '1 hour'), ('480', '8 hours'), ('1440', '1 day') ], default="0", validators=[validators.Optional()])
