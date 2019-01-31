"""
Reusable web utilties
"""
#standard libraries
import json
import logging
import calendar
import time

#3rd party libraries
import falcon
from bson.objectid import ObjectId


class WebUtil(object):
    """
    Various web utils
    """

    def __init__(self, cfg):
        self.logger = logging.getLogger('app')
        self.cfg = cfg

    def parse_json_body(self, req_body):
        """
        parse the body of a jason
        """
        try:
            raw_json = req_body
            result = json.loads(raw_json.decode())
            self.logger.debug("parse_json_body received: %s", str(result))
        except ValueError:
            raise falcon.HTTPError(
                falcon.HTTP_400,
                'Invalid JSON',
                'Could not decode the request body - Incorrect JSON.'
                )
        return result


    def check_csrf(self, user_session, req_headers):
        """
        Validate a csrf_token
        """
        #if the csrf token doesn't match the first 3 chars of the session
        #self.logger.debug('testing csrf:'
        # + user_session[:3] + ' ' + csrf_token)
        if 'X-CSRF' not in req_headers or user_session[:3] != req_headers['X-CSRF']:
            self.logger.debug("CSRF Check Failed, throwing 401")
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Error',
                'CSRF Rejected'
                )
        else:
            return True

    def check_grant(self, security_context, user_token, grant_req):
        """
        Test if requestest action is permitted
        """
        self.logger.debug("Checking Grants %s  %s",
                          security_context, json.dumps(user_token))
        #security_context is stored as a string in the user token json
        security_context = str(security_context)

        if security_context not in user_token['grants']:
            self.logger.debug(
                'Action blocked: %s/%s denied to %s because of context',
                security_context,
                grant_req,
                user_token['username']
                )
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Request Denied - Security Context',
                "The '{user}' user does not have privileges in the "
                "'{security_context}' "
                "security context.  Request to exercise the '{grant}' "
                "privilege Denied.".format(
                    user=user_token['username'],
                    security_context=security_context,
                    grant=grant_req)
                )
        if grant_req in user_token['grants'][security_context]:
            self.logger.debug(
                'check_grant allowed %s for: %s',
                grant_req,
                user_token['username']
            )
        else:
            self.logger.debug(
                'check_grant denied %s/%s to %s because of grant',
                security_context,
                grant_req,
                user_token['username']
                )
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden

                'Request Denied - Insufficient Privilege',
                "The '{user}' user does not have the '{grant}' "
                "privilege in the '{security_context}' "
                "security context.".format(
                    user=user_token['username'],
                    security_context=security_context,
                    grant=grant_req)
                )

    def test_id_from_web(self, web_id, function, user_token):
        """
        Check for malicious activity, verify id's from web are ints
        """
        try:
            return int(web_id)
        except:
            self.logger.debug(
                'Unusual Activity %s not int: %s throwing 400',
                function,
                user_token['username']
                )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                "INVALID ID in URL"
                )
    def test_oid_from_web(self, web_id, function, user_token):
        """
        Check for malicious activity, verify id's from web are ints
        """
        try:
            return ObjectId(web_id)
        except:
            self.logger.debug(
                'Unusual Activity not oid on %s attempt: throwing 400 for %s',
                function,
                user_token['username']
                )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Error',
                "INVALID ID in URL"
                )

    def test_captcha(self, captcha_response):
        """
        Test if the reponds correctly answers the captcha challenge
        """
        if captcha_response == 'abc~def1':
            return True
        else:
            return False

    def get_captcha(self):
        """
        create a captcha challenge
        """
        return 'abc~def'

    def recursive_sanitize(self, obj):
        """
        sanitize a dict tree through all nodes
        """
        for key, val in obj.items():
            if isinstance(val, collections.Mapping): #pylint: disable=undefined-variable
                obj[key] = self.recursive_sanitize(obj.get(key, {}))
            elif isinstance(val, str):
                obj[key] = bleach.clean(val)#pylint: disable=undefined-variable
        return obj

    def post_session_creation(self, user_token):
        """
        used by sessionrefreshresource and auth resource to modify the jwt
        cooke for  application varibles that won't be protected by
        httponly.
        """
        csrf_token = user_token['ses'][:3]
        user_token['csrf'] = csrf_token
        self.logger.debug("USER PROFILE: %s", json.dumps(user_token))
        #session id should only be in the cookie, never the dom
        del user_token['ses']
        user_token['est_ses_exp'] = calendar.timegm(time.gmtime()) \
          + self.cfg.MAX_UNAUTH_SESSION_DURATION - 10
        #package the sanitized uesr profile and send back to client
        return json.dumps(user_token)
