"""
SecurityContext Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps

#App specific libraries
from genesis.securitycontextdbhelper import SecurityContextDBHelper


class SecurityContextResource(object):
    """
    Falcon web request handlers for security_contexts
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util


    def on_get(self, req, resp, security_context='system', security_context_id=''):
        """
        Handles GET requests - returns a security_context object from DB
        """
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if security_context is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'SEL_SEC_CONTEXT')


            #Initialize Database components
            security_context_helper = SecurityContextDBHelper(self.pers)
            if security_context_id != '':
                self.logger.debug('searching for %s', security_context_id)
                security_context = security_context_helper.sel(
                    security_context,
                    security_context_id
                    )
                self.logger.debug('found %s', dumps(security_context))
            else:
                security_context = security_context_helper.sel_list(security_context)
                self.logger.debug('Result Count %s', str(len(security_context)))
            resp.body = dumps(security_context)

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


    def on_post(self, req, resp, security_context):
        """
        Handles POST requests - Inserts a security_context
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            security_context_req = self.web_util.parse_json_body(req.stream.read())
            #self.logger.debug('Posted Data: ' + dumps(security_context_req))

            #Gaurd against CSRF
            self.web_util.check_csrf(user_token['ses'], req.headers)

            self.web_util.check_grant(security_context, user_token, 'INS_SEC_CONTEXT')

            #override any hijinks
            security_context_req['createUser'] = user_token['username']
            security_context_req['updateUser'] = user_token['username']



            security_context_helper = SecurityContextDBHelper(self.pers)
            security_context_check = security_context_helper.is_valid_security_context(
                security_context_req,
                goal='INS'
                )

            if security_context_check == "OK":
                security_context = security_context_helper.ins(
                    security_context,
                    security_context_req
                    )
            else:
                self.logger.debug(
                    'security_contextcheck Failed: %s',
                    security_context_check
                )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'SecurityContext Integrity Check Failed',
                    security_context_check
                )

            #http://www.restapitutorial.com/lessons/httpmethods.html
            resp.status = falcon.HTTP_201
            resp.body = dumps(security_context)
        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_post failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )

    def on_put(self, req, resp, security_context):
        """
        Handles PUT requests - updates a security_context
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            security_context_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(
                security_context,
                user_token,
                'UPD_SEC_CONTEXT'
                )


            security_context_helper = SecurityContextDBHelper(self.pers)
            security_context_req['updateUser'] = user_token['username']
            #Confirm object is valid for database update
            security_context_check = security_context_helper.is_valid_security_context(
                security_context_req,
                'UPD'
                )

            if security_context_check == "OK":
                self.logger.debug('object passed validation for update')
                security_context = security_context_helper.upd(
                    security_context,
                    security_context_req
                    )
                resp.body = dumps(security_context)
            else:
                self.logger.debug(
                    'object failed falication for update: %s',
                    security_context_check
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'SecurityContext Integrity Check Failed',
                    security_context_check
                    )
            if  not security_context:
                self.logger.debug(
                    'problem in update, throwing 406'
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_406,
                    'Something went wrong at the server.',
                    'Someone is already queued to research the issue.'
                    )

        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_put failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )

    def on_delete(self, req, resp, security_context, security_context_id):
        """
        Handles on Delete - Deletes a security_context
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            self.web_util.check_grant(security_context, user_token, 'DEL_SEC_CONTEXT')

            #on_delete can ignore the body,
            #likely to be dropped in web proxies anyway
            #valid_security_context_test not required
            security_context_helper = SecurityContextDBHelper(self.pers)
            security_context_helper.drp(security_context, security_context_id)
            resp.status = falcon.HTTP_200 #S=200 response signals success
            resp.body = "1"

        except falcon.HTTPError:
            raise
        except Exception:
            self.logger.error(
                "on_delete failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )
