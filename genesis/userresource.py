"""
User Web service
"""
#Standard Libraries
import json
import logging
import traceback

#Third Party Libraries
import falcon
import bcrypt
from bson.json_util import dumps

#App specific libraries
from genesis.userdbhelper import UserDBHelper


class UserResource(object):
    """
    Falcon web request handlers for users
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util


    def on_get(self, req, resp, user_id='', security_context=''):
        """
        Handles GET requests - returns a user object from DB
        """
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            self.logger.debug("token: %s", json.dumps(req.context['user']))

            #Check to see if user is permitted to select in this context
            self.logger.debug("security_context: %s", security_context)
            self.web_util.check_grant(security_context, user_token, 'SEL_USER')


            #Initialize Database components
            user_helper = UserDBHelper(self.pers)
            if user_id != '':
                user = user_helper.sel(security_context, user_id)
            else:
                user = user_helper.sel_list(security_context)
            resp.body = dumps(user)

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
        Handles POST requests - Inserts a user
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            user_req = self.web_util.parse_json_body(req.stream.read())
            self.logger.debug('Posted Data: %s', dumps(user_req))

            #Gaurd against CSRF
            self.web_util.check_csrf(user_token['ses'], req.headers)
            # Check users permissions
            self.web_util.check_grant(security_context, user_token, 'INS_USER')

            #override any hijinks
            user_req['createUser'] = user_token['username']
            user_req['updateUser'] = user_token['username']
            user_req['securityContext'] = security_context
            user_req['userGrants'] = '{"1":["LOGON"]}' #grants must be checked separately

            #hash password

            password_hash = bcrypt.hashpw(
                str(user_req['passwd']).encode('utf-8'), bcrypt.gensalt()
                )
            user_req['passwdHash'] = password_hash
            del user_req['passwd']

            user_helper = UserDBHelper(self.pers)
            user_check = user_helper.is_valid_user(user_req, goal='INS')

            if user_check == "OK":
                user = user_helper.ins(user_req)

                if user == "DUP":
                    raise falcon.HTTPError(
                        falcon.HTTP_409,
                        'Duplicate Email/User Name',
                        'That username or email is already assigned.'
                    )
                else:
                    del user['passwdHash']

            else:
                self.logger.debug('usercheck Failed: %s', user_check)
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'User Integrity Check Failed',
                    user_check
                )

            #http://www.restapitutorial.com/lessons/httpmethods.html
            resp.status = falcon.HTTP_201
            resp.body = dumps(user)
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
        Handles PUT requests - updates a user
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            user_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            # Check users permissions
            self.web_util.check_grant(security_context, user_token, 'UPD_USER')
            user_helper = UserDBHelper(self.pers)
            user_req['updateUser'] = user_token['username']
            del user_req['passwd'] # passwd may come through the client, but not changed here
            #Confirm object is valid for database update
            user_check = user_helper.is_valid_user(user_req, 'UPD')
            if user_check == "OK":
                self.logger.debug('object passed validation for update')
                #if attempting a context change, must have insert in the new context
                if security_context != user_req['securityContext']:
                    self.web_util.check_grant(user_req['securityContext'], user_token, 'INS_USER')
                user = user_helper.upd(security_context, user_req)
                if user == 'DUP':
                    raise falcon.HTTPError(
                        falcon.HTTP_403,
                        'Duplicate Email/User Name',
                        'That username or email is already assigned.'
                    )
                resp.body = dumps(user)
            else:
                self.logger.debug(
                    'object failed validation for update: %s',
                    user_check
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'User Integrity Check Failed',
                    user_check
                    )
            if not user:
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

    def on_delete(self, req, resp, user_id, security_context):
        """
        Handles on Delete - Deletes a user
        """
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'DEL_USER')

            #on_delete can ignore the body,
            #likely to be dropped in web proxies anyway
            #valid_user_test not required
            user_helper = UserDBHelper(self.pers)
            user_helper.drp(security_context, user_id)
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
