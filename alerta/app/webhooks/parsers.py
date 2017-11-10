import json
import re

from alerta.app import app, db
from alerta.app.utils import absolute_url

from flask.config import Config


class ConfigParser(object):

    def __init__(self, logger=None):
        self.logger = logger if logger else app.logger
        super(ConfigParser, self).__init__()

    def get_customer_config(self, customer="default"):
        """
        Get customer config file.
        """
        try:
            return self._get_config(customer=customer)
        except Exception as e:
            pass

        try:
            return self._get_config()
        except Exception as e:
            return Config('/')

    def _get_config(self, customer="default"):
        """
        Get customer or default config file according customer name.
        """
        config, customer = Config('/'), "_{}".format(customer)
        try:
            loaded = config.from_pyfile("/etc/alertad{}.conf".format(customer), silent=False)
        except Exception as e:
            loaded = False
        try:
            config.from_envvar("ALERTA_SVR_CONF{}_FILE".format(customer.upper()), silent=False)
        except Exception as e:
            if loaded:
                return config
            raise e
        return config

    def get_default_config(self):
        """
        Get application config file.
        """
        from alerta.app import app
        return app.config


class SlackParser(ConfigParser):

    messages = {
        'alert_not_found': u"Alert {alert} not found.",
        'user_not_found': u"User {user} not found.",
        'action_not_found': u"Action {action} not found.",
        'loading_error': u"Error getting configuration by {customer} customer.\n Telegram reply for {action} on "
                         u"{alert} won't be sent.",
        'reply_message': u":white_check_mark: Alert {alert} is {status} now! Action done by @{user}.",
        'reply_watching_message': u":small_blue_diamond: User @{user} is watching alert {alert}.",
    }

    def parse_slack(self, data):
        """
        Parser request data to get `alert`, `user` and `action`.
        """
        payload = json.loads(data['payload'])

        user = payload.get('user', {}).get('name')
        alert_key = payload.get('callback_id')
        action = payload.get('actions', [{}])[0].get('value')

        params = {'action': action, 'user': user, 'alert': alert_key}
        try:
            alert = db.get_alert(id=alert_key)
        except Exception as e:
            raise ValueError(self.messages['alert_not_found'].format(**params))

        if not user:
            raise ValueError(self.messages['user_not_found'].format(**params))
        elif not action:
            raise ValueError(self.messages['action_not_found'].format(**params))

        return alert, user, action

    def build_slack_response(self, alert, action, user, data):
        """
        Send the response message and sent request to add it.
        """
        response = json.loads(data['payload']).get('original_message', {})
        actions = ['open', 'ack', 'close']

        alert_short_id = alert.get_id(short=True)
        params = {'action': action, 'alert': alert_short_id, 'customer': alert.customer}

        try:
            customer_config = self.get_customer_config(alert.customer)
        except Exception as e:
            customer_config = {}
            self.logger.warning(self.messages['loading_error'].format(**params))

        reply = customer_config.get('SLACK_REPLY_FORMAT', self.messages['reply_message'])
        reply_watching = customer_config.get('SLACK_REPLY_WATCHING_FORMAT', self.messages['reply_watching_message'])
        message = (reply if action in actions else reply_watching).format(
            alert=alert.get_id(short=True), status=alert.status, action=action, user=user
        )

        attachment_response = {"fallback": message, "color": "#808080", "title": message}
        if action in actions:
            attachment_response.update({
                "title_link": absolute_url("{}/alert/{}".format(app.config.get('DASHBOARD_URL'), alert.id))
            })

        # clear interactive buttons and add new attachment as response of action
        attachments = response.get('attachments', [])
        if action in actions:
            for attachment in attachments:
                attachment.pop('actions', None)

        attachments.append(attachment_response)
        response['attachments'] = attachments
        return response


class TelegramParser(ConfigParser):

    messages = {
        'dependencies': u"You have configured Telegram but 'telepot' client is not installed.",
        'data_expected': u"Token, dashboard url and channel id are expected to send notification for {action} on "
                         u"{alert} of {customer} customer.",
        'loading_error': u"Error getting configuration by {customer} customer.\n Telegram reply for {action} on "
                         u"{alert} won't be sent.",
        'message_format': u"{alarm} `{level}` - *{event}*\n"
                          u"`Resource: {resource}`\n"
                          u"`Customer: {customer}`\n"
                          u"{services_as_text}"
                          u"`Severity: {severity}`\n"
                          u">> {text}",
        'extra_message_format': u"{log}\n{reply}",
        'reply_message': u"\u2713 Alert {alert} is *{status}* now! Action done by {user}.",
        'reply_watching_message': u"\u23F5 User {user} is watching alert {alert}.",
        'sending_error': u"Error sending reply message for {action} on {alert}."
    }

    @staticmethod
    def valid_data(data):
        """
        Validate id `callback_query` is in data dict
        """
        return data and 'callback_query' in data

    def parser_telegram(self, data):
        """
        Parser request data to get `alert`, `user` and `action`.
        """
        author = data['callback_query']['from']
        command, alert = data['callback_query']['data'].split(' ', 1)
        action = command.lstrip('/')

        user = author.get('username')
        if not user:
            user = u"{} {}".format(author.get('first_name'), author.get('last_name') or '').strip(' ')

        return alert, user, action

    def _chat_id(self, data):
        """
        The channel id for response. Get it from request message
        """
        return data['callback_query']['message']['chat']['id']

    def _message_log(self, data):
        """
        Parser text message text to find the original message.
        Try to find the text between '>>' and '\n' characters as end of original message.
        """
        message = data['callback_query']['message']['text']
        search = re.search(">>\s*(?P<text>(?!\n).*)", message)
        if not search:
            return message
        text = search.group('text')
        message = message[message.index(text) + len(text):]
        for char in ('\n', ' '):
            message = message.strip(char)
        message = u"\n{}".format(message) if message else message
        return message

    def _services_as_text(self, alert):
        return u"`Services: {}`\n".format(u", ".join(alert.service)) if alert.service else u""

    def _reply_message(self, action, alert, user, config):
        """
        Get the format of the reply message.
        It can be configured for each customer in their config files.
        """
        reply = config.get('TELEGRAM_REPLY_FORMAT', self.messages['reply_message'])
        if action == 'watch':
            reply = config.get('TELEGRAM_REPLY_WATCHING_FORMAT', self.messages['reply_watching_message'])
        reply = unicode(reply).format(alert=alert, status=action, user=user)
        return reply

    def _get_message_format(self, config):
        """
        Recovery the format of original message to keep it when response (update it).
        It can be configured for each customer in their config files.
        """
        msg = config.get('TELEGRAM_MESSAGE_FORMAT', self.messages['message_format'])
        extra_msg = config.get('TELEGRAM_EXTRA_MESSAGE_FORMAT', self.messages['extra_message_format'])
        return u"{}{}".format(unicode(msg), unicode(extra_msg))

    def send_message_reply(self, alert_id, action, user, data):
        """
        Send the response message and sent request to update it.
        """
        try:
            import telepot
        except ImportError as e:
            self.logger.warning(self.messages['dependencies'], exec_info=True)
            return

        # process buttons for reply text
        alert = db.get_alert(alert_id)
        alert_short_id = alert.get_id(short=True)

        inline_keyboard = []
        params = {'action': action, 'alert': alert_short_id, 'customer': alert.customer}

        try:
            customer_config = self.get_customer_config(alert.customer)
            config = self.get_default_config()

            token = customer_config.get('TELEGRAM_TOKEN')
            dashboard_url = config.get('DASHBOARD_URL')

            chat_id = self._chat_id(data)
            if not (token and dashboard_url and chat_id):
                raise ValueError(self.messages['data_expected'].format(**params))
        except Exception as e:
            self.logger.error(self.messages['loading_error'].format(**params))
            return

        try:
            # message info
            message_id = data['callback_query']['message']['message_id']
            message_log = self._message_log(data)
            message_format = self._get_message_format(customer_config)

            if action == 'watch':
                inline_keyboard = [
                    [{'text': 'Watch', 'callback_data': "{} {}".format('/watch', alert_id)},
                     {'text': 'Ack', 'callback_data': "{} {}".format('/ack', alert_id)},
                     {'text': 'Close', 'callback_data': "{} {}".format('/close', alert_id)}, ]
                ]

            # format message response
            text = alert.text.replace('_', '\_')
            alert_url = "{}/#/alert/{}".format(dashboard_url, alert.id)
            reply = self._reply_message(action, alert_short_id, user, customer_config)
            severity = u"{} \u2192 {}".format(alert.previous_severity or 'indeterminate', alert.severity)
            message = message_format.format(
                alarm="[{}]({})".format(alert_short_id, alert_url), level=alert.severity.upper(), event=alert.event,
                resource=alert.resource, customer=alert.customer, severity=severity, text=text, log=message_log,
                reply=reply, services_as_text=self._services_as_text(alert)
            )

            # send message
            bot = telepot.Bot(token)
            bot.editMessageText(msg_identifier=(chat_id, message_id), text=message, parse_mode='Markdown',
                                reply_markup={'inline_keyboard': inline_keyboard})
        except Exception as e:
            params = {'action': action, 'alert': alert_id}
            self.logger.warning(self.messages['sending_error'].format(**params), exc_info=True)

