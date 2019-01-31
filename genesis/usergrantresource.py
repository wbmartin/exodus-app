"""
User Web service
"""
#Standard Libraries
import logging
import traceback



#Third Party Libraries
import falcon



#App specific libraries
from genesis.userdbhelper import UserDBHelper


class UserGrantResource(object):
    """
    Falcon web request handlers for users
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util

    def on_put(self, req, resp, security_context, user_id):
        """
        Handles PUT requests - updates a user
        """
        try:
            user_token = req.context['user']['user']
            self.web_util.check_grant(security_context, user_token, 'UPD_USER')
            self.logger.debug("testing userid %s", str(user_id))
            user_id = self.web_util.test_oid_from_web(
                str(user_id),
                'put-user_id',
                user_token
                )
            #security_context = self.web_util.test_id_from_web(security_context,
            #'put-security_context', user_token)
            if user_id == 0:
                raise RuntimeError
            grant_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            user_helper = UserDBHelper(self.pers)
            #override any hijinks

            user_req = {
                '_id': {'$oid': str(user_id)},
                'updateUserId': user_token['username'],
                'userGrants': grant_req
            }

            user_helper.upd(security_context, user_req)


        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_put failed: %s",
                traceback.print_exc()
                )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                "INTERNAL"
            )
