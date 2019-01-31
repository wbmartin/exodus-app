"""
Authentication Resource for falcon framework authentication

"""
#Standard Libraries
import logging
import traceback
from datetime import datetime

#3rd Party Libraries
import falcon

#Local app libraries
from genesis.userdbhelper import UserDBHelper



class AuthResource(object):
    """
    Web Front Facing authentication and authorization
    """
    def __init__(self, persistence, webuser_auth_backend, cfg, web_util, session_manager):
        """
        Initialization function
        """
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.auth_backend = webuser_auth_backend
        self.cfg = cfg
        self.persistence = persistence
        self.web_util = web_util
        self.session_manager = session_manager

    def on_post(self, req, resp):
        """
        Process post request - validate User credentials return user object
        """
        try:
            self.logger.debug("on_post Called")
            #Limit size of input, filter for malicious activity
            #extra precaution for public facing function before parsing body
            req_body = req.stream.read()
            if len(req_body) > 1000:
                self.logger.warning("Potential malicious activity")
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'Error',
                    "Request Body too long"
                )

            result = self.web_util.parse_json_body(req_body)

            #Extra validations because this is Auth bypassed in middleware
            #Validate username and password are reasonable
            if len(result["username"]) < 75 and len(result["passwd"]) < 75:
                helper = UserDBHelper(self.persistence)
                self.logger.debug("***User: %s", result['passwd'])
                user_profile = helper.authenticate_user(
                    username=result["username"],
                    passwd=result["passwd"]
                )
            else:
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'Error',
                    "Username or password too long"
                )

            #if the user creds authenticated
            #then a dictionary object with grants was returned
            if isinstance(user_profile, dict):
                self.session_manager.start_session(user_profile['ses'])
                jwt_payload = self.auth_backend.get_auth_token(user_payload=user_profile)
                resp.set_cookie(
                    'jwt',
                    jwt_payload,
                    secure=self.cfg.REQUIRE_SECURE_COOKIES,
                    http_only=True,
                    path="/",
                    domain=self.cfg.COOKIE_DOMAIN
                )
                resp.body = self.web_util.post_session_creation(user_profile)
                del jwt_payload
            else:
                resp.set_cookie(
                    'jwt',
                    'DENIED',
                    secure=self.cfg.REQUIRE_SECURE_COOKIES,
                    path="/",
                    http_only=True,
                    domain=self.cfg.COOKIE_DOMAIN
                )
                self.logger.error(
                    "throwing 401 User Not Found"
                )
                raise falcon.HTTPError(falcon.HTTP_401, 'Error', 'INTERNAL')
            #Try to purge the password from memory
            del result['passwd']
        except falcon.HTTPError:
            raise
        except Exception:
            self.logger.error(
                "Select failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                "INTERNAL"
            )
    def on_delete(self, req, resp):
        """
        Process post request - validate User credentials return user object
        """
        try:
            self.logger.debug("on_delete Called")
            resp.set_cookie(
                'jwt',
                'DELETED',
                secure=self.cfg.REQUIRE_SECURE_COOKIES,
                expires=datetime(year=1970, month=1, day=1),
                http_only=True,
                path="/",

                domain=self.cfg.COOKIE_DOMAIN
            )
        except falcon.HTTPError:
            raise
        except Exception:
            self.logger.error(
                "Select failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                "INTERNAL"
            )
