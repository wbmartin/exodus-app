"""
New User Resource Class
"""
# Standard Libraries

import logging
import traceback

#3rd party libraries
import falcon
import bcrypt
import bson


#application libraries

from genesis.userdbhelper import UserDBHelper


class AnonNewUserResource(object):
    """ Falcon Handlers for web interaction """
    def __init__(self, persistence, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("New User Resource instantiated")
        self.cfg = cfg
        self.persistence = persistence
        self.web_util = web_util

    def on_post(self, req, resp):
        """
        Handle Post Submission
        """
        #TODO There is a very similar function in userresourc.py. consolidate?
        # around line 66
        try:
            self.logger.debug("on_post_helper anon_new user resource")
            #If anonymous user creation is allowed or if the
            if self.cfg.PERMIT_ANON_USER_CREATE:
                #If you want to restrict this to Admin created users,
                #you need to remove the middleware exempt route and
                #change the authorization check to this:
                #'CREATE_USER' in user_token['grants']["1"]:
                #and add this check above
                #user_token = req.context['user']['user']

                #The functionality was offloaded to a helper
                #so it can be used for admin created users as well

                self.logger.debug("on_post_helper running")
                result = self.web_util.parse_json_body(req.stream.read())
                password_hash = bcrypt.hashpw(
                    str(result['passwd']).encode('utf-8'), bcrypt.gensalt()
                    )

                #Define the basic Grants to assign the user upon creation
                grants = '{"1":["LOGON"]}'
                user_req = {
                    'username': str(result['username']),
                    'email': str(result['email']),
                    '_id': 0,
                    'passwdHash': password_hash,
                    'userGrants': grants,
                    'securityContext': 'system', #Default Context for anonymous users
                    'createUser': 'self-web-request',
                    'updateUser': ''
                }
                user_db_helper = UserDBHelper(self.persistence)
                user_validity = user_db_helper.is_valid_user(user_req, goal='INS')
                if user_validity != "OK":
                    raise falcon.HTTPError(
                        falcon.HTTP_400,
                        'Invalid Username/password request',
                        user_validity
                    )

                created_user = user_db_helper.ins(
                    user_req,
                    )
                #correctly created user will be returned as a dictionary
                if (isinstance(created_user, dict)
                        and '_id' in created_user
                        and bson.objectid.ObjectId.is_valid(created_user['_id'])
                   ):
                    error_msg = ""
                else:
                    error_msg = "Insert Error - Perhaps User Exists"

                if error_msg != "":
                    raise falcon.HTTPError(
                        falcon.HTTP_400,
                        'ERROR',
                        error_msg
                    )
            else:
                self.logger.debug('Anonymous user create attempted')
                raise falcon.HTTPError(
                    falcon.HTTP_401, #Forbidden
                    'Error',
                    'Anonymous User Creation Not permitted'
                )

        except falcon.HTTPError:
            raise
        except:
            self.logger.error("Select failed: %s",
                              traceback.print_exc()
                             )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                'INTERNAL'
            )
