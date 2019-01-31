"""
PasswordReset Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon

#App specific libraries


class SessionRefreshResource(object):
    """
    Falcon web request handlers for password reset requests
    """

    def __init__(self, persistence, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.cfg = cfg
        self.web_util = web_util


    def on_get(self, req, resp, security_context=''):
        """
        Handles GET requests - refreshes the client session variable based on the cookie
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if note_entry is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'LOGON')
            resp.body = self.web_util.post_session_creation(user_token)

        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_get failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )
