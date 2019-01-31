"""
UserGroup Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps

#App specific libraries
from genesis.usergroupdbhelper import UserGroupDBHelper


class UserGroupResource(object):
    """
    Falcon web request handlers for user_groups
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util


    def on_get(self, req, resp, security_context='', user_group_id=''):
        """
        Handles GET requests - returns a user_group object from DB
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if user_group is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'SEL_USER_GROUP')


            #Initialize Database components
            user_group_helper = UserGroupDBHelper(self.pers)
            if user_group_id != '':
                self.logger.debug('searching for %s', user_group_id)
                user_group = user_group_helper.sel(security_context, user_group_id)
                self.logger.debug('found %s', dumps(user_group))
            else:
                user_group = user_group_helper.sel_list(security_context)
                self.logger.debug('Result Count %s', str(len(user_group)))
            resp.body = dumps(user_group)

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
        Handles POST requests - Inserts a user_group
        """
        self.logger.debug('on_post running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            user_group_req = self.web_util.parse_json_body(req.stream.read())
            self.logger.debug('Posted Data: %s', dumps(user_group_req))

            #Guard against CSRF
            self.web_util.check_csrf(user_token['ses'], req.headers)

            self.web_util.check_grant(security_context, user_token, 'INS_USER_GROUP')

            #override any hijinks
            user_group_req['createUser'] = user_token['username']
            user_group_req['updateUser'] = user_token['username']
            user_group_req['securityContext'] = security_context


            user_group_helper = UserGroupDBHelper(self.pers)
            user_group_check = user_group_helper.is_valid_user_group(user_group_req, goal='INS')

            if user_group_check == "OK":
                self.logger.debug('Object passed validation for insert')
                user_group = user_group_helper.ins(security_context, user_group_req)
            else:
                self.logger.debug('user_groupcheck Failed: %s', user_group_check)
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'UserGroup Integrity Check Failed',
                    user_group_check
                )

            #http://www.restapitutorial.com/lessons/httpmethods.html
            resp.status = falcon.HTTP_201
            resp.body = dumps(user_group)
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
        Handles PUT requests - updates a user_group
        """
        self.logger.debug('on_put running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            user_group_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'UPD_USER_GROUP')

            user_group_helper = UserGroupDBHelper(self.pers)
            user_group_req['updateUser'] = user_token['username']
            #Confirm object is valid for database update
            user_group_check = user_group_helper.is_valid_user_group(user_group_req, 'UPD')

            if user_group_check == "OK":
                self.logger.debug('object passed validation for update')
                user_group = user_group_helper.upd(security_context, user_group_req)
                resp.body = dumps(user_group)
            else:
                self.logger.debug(
                    'Update Failed, throwing 400: %s',
                    user_group_check
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'UserGroup Integrity Check Failed',
                    user_group_check
                    )
            if not user_group:
                self.logger.debug('Update Failed, throwing 406')
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

    def on_delete(self, req, resp, security_context, user_group_id):
        """
        Handles on Delete - Deletes a user_group
        """
        self.logger.debug('on_del running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'DEL_USER_GROUP')

            #on_delete can ignore the body,
            #likely to be dropped in web proxies anyway
            #valid_user_group_test not required
            user_group_helper = UserGroupDBHelper(self.pers)
            user_group_helper.drp(security_context, user_group_id)
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
