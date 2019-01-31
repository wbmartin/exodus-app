"""
AppGrant Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps

#App specific libraries
from genesis.appgrantdbhelper import AppGrantDBHelper


class AppGrantResource(object):
    """
    Falcon web request handlers for app_grants
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util


    def on_get(self, req, resp, security_context='', app_grant_id=''):
        """
        Handles GET requests - returns a app_grant object from DB
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if app_grant is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'SEL_APP_GRANT')


            #Initialize Database components
            app_grant_helper = AppGrantDBHelper(self.pers)
            if app_grant_id != '':
                self.logger.debug('searching for %s', app_grant_id)
                app_grant = app_grant_helper.sel(security_context, app_grant_id)
                self.logger.debug('found %s', dumps(app_grant))
            else:
                app_grant = app_grant_helper.sel_list(security_context)
                self.logger.debug('Result Count %s', str(len(app_grant)))
            resp.body = dumps(app_grant)

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
        Handles POST requests - Inserts a app_grant
        """
        self.logger.debug('on_post running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            app_grant_req = self.web_util.parse_json_body(req.stream.read())
            self.logger.debug('Posted Data: %s', dumps(app_grant_req))

            #Guard against CSRF
            self.web_util.check_csrf(user_token['ses'], req.headers)

            self.web_util.check_grant(security_context, user_token, 'INS_APP_GRANT')

            #override any hijinks
            app_grant_req['createUser'] = user_token['username']
            app_grant_req['updateUser'] = user_token['username']
            app_grant_req['securityContext'] = security_context


            app_grant_helper = AppGrantDBHelper(self.pers)
            app_grant_check = app_grant_helper.is_valid_app_grant(app_grant_req, goal='INS')

            if app_grant_check == "OK":
                self.logger.debug('Object passed validation for insert')
                app_grant = app_grant_helper.ins(security_context, app_grant_req)
            else:
                self.logger.debug('app_grantcheck Failed: %s', app_grant_check)
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'AppGrant Integrity Check Failed',
                    app_grant_check
                )

            #http://www.restapitutorial.com/lessons/httpmethods.html
            resp.status = falcon.HTTP_201
            resp.body = dumps(app_grant)
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
        Handles PUT requests - updates a app_grant
        """
        self.logger.debug('on_put running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            app_grant_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'UPD_APP_GRANT')

            app_grant_helper = AppGrantDBHelper(self.pers)
            app_grant_req['updateUser'] = user_token['username']
            #Confirm object is valid for database update
            app_grant_check = app_grant_helper.is_valid_app_grant(app_grant_req, 'UPD')

            if app_grant_check == "OK":
                self.logger.debug('object passed validation for update')
                app_grant = app_grant_helper.upd(security_context, app_grant_req)
                resp.body = dumps(app_grant)
            else:
                self.logger.debug(
                    'Update Failed, throwing 400: %s',
                    app_grant_check
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'AppGrant Integrity Check Failed',
                    app_grant_check
                    )
            if not app_grant:
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

    def on_delete(self, req, resp, security_context, app_grant_id):
        """
        Handles on Delete - Deletes a app_grant
        """
        self.logger.debug('on_del running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'DEL_APP_GRANT')

            #on_delete can ignore the body,
            #likely to be dropped in web proxies anyway
            #valid_app_grant_test not required
            app_grant_helper = AppGrantDBHelper(self.pers)
            app_grant_helper.drp(security_context, app_grant_id)
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
