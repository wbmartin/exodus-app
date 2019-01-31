"""
GoogleAuthentication Resource for falcon framework authentication

"""
#Standard Libraries
import logging
import traceback
import json

#3rd Party Libraries
import falcon
from google.oauth2 import id_token
from google.auth.transport import requests

#Local app libraries
from genesis.userdbhelper import UserDBHelper



class GoogleAuthResource(object):
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

    #TODO - consolidate with authresource
    def on_post(self, req, resp):
        """
        Process post request - validate User credentials return user object
        """
        self.logger.debug("on_post Called")
        try:
            user_profile = {}
            #Limit size of input, filter for malicious activity
            #extra precaution for public facing function before parsing body
            req_body = req.stream.read()
            if len(req_body) > 1200:
                self.logger.warning("Potential malicious activity")
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'Error',
                    "Request Body too long" + str(len(req_body))
                )

            result = self.web_util.parse_json_body(req_body)
            #self.logger.debug("result:" + json.dumps(result))

            #Extra validations because this is GoogleAuth bypassed in middleware
            #Validate username and password are reasonable
            if ("idToken" in result and "clientId" in result and
                    len(result["idToken"]) < 1000 and
                    len(result["clientId"]) < 150):
                helper = UserDBHelper(self.persistence)
                #self.logger.debug("***token:" + result['idToken'])

                google_email = self.googleauth(result["idToken"], result["clientId"])
                self.logger.debug('email: %s', google_email)
                if isinstance(google_email, str):
                    self.logger.debug('Google Validated %s', google_email)
                    db_record = helper.sel_by_email(
                        'system',
                        google_email
                    )

                    if len(db_record) != 1:
                        user_profile = {}
                        self.logger.debug("throwing 400, dup or no email detected - 73")
                        raise falcon.HTTPError(
                            falcon.HTTP_400,
                            'Error',
                            'Intnernal Error'
                        )
                    else:
                        user_profile = helper.post_authentication_processing(db_record[0])
                        self.logger.debug("Database knew %s", google_email)
                else:
                    self.logger.debug('Google Validation failed')
            else:
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'Error',
                    "clientId or idToken too long or not present"
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
                self.logger.error(
                    "Throwing 401 Unknown email"
                )
                resp.set_cookie(
                    'jwt',
                    'DENIED',
                    secure=self.cfg.REQUIRE_SECURE_COOKIES,
                    http_only=True
                )
                raise falcon.HTTPError(
                    falcon.HTTP_401, #Denied
                    'Error',
                    "Unknown Email"
                )
            #Try to purge the password from memory
            #del result['passwd']
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
    def googleauth(self, req_id_token, client_id):
        """
        execute a google auth request
        """
        self.logger.debug(
            "googleauth running"
        )
        email = False
        #request = requests.Request()
        id_info = id_token.verify_oauth2_token(
            req_id_token,
            requests.Request(),
            self.cfg.GOOGLE_OAUTH_CLIENT_ID
            )
        self.logger.debug(json.dumps(id_info))
        if id_info['iss'] != 'accounts.google.com':

            userid = id_info['sub']
            self.logger.debug(
                "userid %s", userid
            )
            raise ValueError('Wrong issuer.')
        if 'email' in id_info and id_info['email_verified']:
            email = id_info['email']
        else:
            email = False
        return email
