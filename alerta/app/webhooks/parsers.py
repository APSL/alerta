import json

from alerta.app import app, db
from alerta.app.utils import absolute_url

from flask.config import Config


class ConfigParser(object):

    def __init__(self, logger=None):
        self.logger = logger if logger else app.logger
        super(ConfigParser, self).__init__()

    def get_customer_config(self, customer="default"):
        try:
            return self._get_config(customer=customer)
        except Exception as e:
            pass

        try:
            return self._get_config()
        except Exception as e:
            return Config('/')

    def _get_config(self, customer="default"):
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
        'reply_message': u"\u2713 Alert {alert} is *{status}* now! Action done by {user}.",
        'reply_watching_message': u"\u23F5 User {user} is watching alert {alert}.",
        'sending_error': u"Error sending reply message for {action} on {alert}."
    }

    @staticmethod
    def valid_data(data):
        return 'callback_query' in data

    def parser_telegram(self, data):
        author = data['callback_query']['from']
        command, alert = data['callback_query']['data'].split(' ', 1)
        action = command.lstrip('/')

        user = author.get('username')
        if not user:
            user = u"{} {}".format(author.get('first_name'), author.get('last_name') or '').strip(' ')

        return alert, user, action

    def send_message_reply(self, alert_id, action, user, data):
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

        # default_reply_message = u""
        # default_reply_watching_message = u""

        try:
            customer_config = self.get_customer_config(alert.customer)
            config = self.get_default_config()

            token = customer_config.get('TELEGRAM_TOKEN')
            chat_id = customer_config.get('TELEGRAM_CHAT_ID')
            dashboard_url = config.get('DASHBOARD_URL')

            if not (token and dashboard_url and chat_id):
                raise ValueError(self.messages['data_expected'].format(**params))
        except Exception as e:
            self.logger.error(self.messages['loading_error'].format(**params))
            return

        try:
            # message info
            message_id = data['callback_query']['message']['message_id']
            message_log = "\n".join(data['callback_query']['message']['text'].split('\n')[1:])
            reply = unicode(customer_config.get('TELEGRAM_REPLY_FORMAT', self.messages['reply_message']))

            if action == 'watch':
                reply = unicode(customer_config.get('TELEGRAM_REPLY_WATCHING_FORMAT',
                                                    self.messages['reply_watching_message']))
                inline_keyboard = [
                    [{'text': 'Watch', 'callback_data': "{} {}".format('/watch', alert_id)},
                     {'text': 'Ack', 'callback_data': "{} {}".format('/ack', alert_id)},
                     {'text': 'Close', 'callback_data': "{} {}".format('/close', alert_id)}, ]
                ]

            # format message response
            alert_url = "{}/#/alert/{}".format(dashboard_url, alert.id)
            reply = reply.format(alert=alert_short_id, status=action, user=user)
            message = u"{alert} `{level}` - *{event} on {resouce}*\n{log}\n{reply}".format(
                alert="[{}]({})".format(alert_short_id, alert_url), level=alert.severity.upper(),
                event=alert.event, resouce=alert.resource, log=message_log, reply=reply)

            # send message
            bot = telepot.Bot(token)
            bot.editMessageText(msg_identifier=(chat_id, message_id), text=message, parse_mode='Markdown',
                                reply_markup={'inline_keyboard': inline_keyboard})
        except Exception as e:
            params = {'action': action, 'alert': alert_id}
            self.logger.warning(self.messages['sending_error'].format(**params), exc_info=True)

