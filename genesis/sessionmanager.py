"""
Minimal Session Management utilities
"""
#Standard libraries
import time
import logging

import falcon


class SessionManager(object):
    """
    Container for session utiltities
    """
    def __init__(self, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.cfg = cfg
        self.web_util = web_util
        self.session_tracker = {}
        self.logger.debug("CHECKING IP EXEMPTIONS")
        for ip_x in self.cfg.ANTIAUTOMATION_EXEMPT_IPS:
            self.logger.debug("IP %s", ip_x)

    def check_unauth_session(self, req, resp):
        """
        Check requests per minute from this IP to prevent automation
        """
        #if the IP address is not already registered create it.
        if req.remote_addr not in self.cfg.ANTIAUTOMATION_EXEMPT_IPS:
            session_id = req.remote_addr
            rpm_status = self.check_rpm_allowed(session_id)
            if rpm_status == 'OK':
                self.logger.debug("ip in rpm allowance %s", session_id)
            elif rpm_status == 'NOSESSION':
                self.logger.debug("Tracking new unauth IP %s", session_id)
                #now = int(time.time())
                self.session_tracker[req.remote_addr] = {
                    'c':1,
                    't':int(time.time())
                }
            elif rpm_status == 'EXCEEDED':
                self.process_captcha(req, resp)
    def check_auth_session(self, req, resp, session_id):
        """
        Check a session_id
        """
         #if the IP address is not already registered create it.
        if session_id not in self.session_tracker:

            self.session_tracker[req.remote_addr] = {
                'c':1,
                't':int(time.time())
            }
            """
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Error',
                "Unknown Session"
            )
            """

        if req.remote_addr not in self.cfg.ANTIAUTOMATION_EXEMPT_IPS:

            rpm_status = self.check_rpm_allowed(session_id)
            if rpm_status == 'OK':
                self.logger.debug("session in rpm allowance %s", session_id)
            #'NOSESSION'not possible, already checked in
            elif rpm_status == 'EXCEEDED':
                self.process_captcha(req, resp)


    def process_captcha(self, req, resp):
        """
        Determine if captcha was needed/successful
        """
        self.logger.debug(
            "RPM over Anti-Automation threshold %s",
            self.cfg.MAX_RPM
            )
        # test the aa cookie if they provided it
        if 'aa' in req.cookies and self.web_util.test_captcha(req.cookies['aa']):
            self.logger.debug('Captcha completed successfully')
            #reset their counter
            now = int(time.time())
            self.session_tracker[req.remote_addr] = {
                'c':1,
                't':now
                }
            resp.unset_cookie('aa')
        #if they provided and failed set new one and throw error
        elif 'aa' in req.cookies:
            self.set_captcha_required(resp)
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Error',
                "Captcha Rejected"
            )
        else:
            self.set_captcha_required(resp)
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Error',
                "Captcha Required"
            )

    def check_rpm_allowed(self, session_id):
        """
        Determine if entitity exceeded allowed requests per minute
        """
        result = ""
        if session_id not in self.session_tracker:
            result = 'NOSESSION'
        else:

            now = int(time.time())
            #grab a reference to the IP's record for easy access
            inst = self.session_tracker[session_id]
            elapsed_time = now - inst['t']
            # increment counter and check for alarm
            inst['c'] += 1
            #Throw exception if captha required and not present
            if inst['c'] > (self.cfg.MAX_RPM):
                result = 'EXCEEDED'
            else:
                result = 'OK'
            #if we're over a minute reset the counter and time
            if elapsed_time > 60:
                self.session_tracker[session_id] = {'c': 1, 't': now}
            self.logger.debug("count %s", self.session_tracker[session_id]['c'])
        return result

    def set_captcha_required(self, resp):
        """
        Set the captcha challenge in a cookie
        """
        resp.set_cookie(
            'aa',
            self.web_util.get_captcha(),
            secure=self.cfg.REQUIRE_SECURE_COOKIES,
            http_only=False, #must be manipulated by client
            path="/",
            domain=self.cfg.COOKIE_DOMAIN
        )
    def end_session(self, session_id):
        """
        Remove session from server
        """
        del self.session_tracker[session_id]

    def start_session(self, session_id):
        """
        Create a session on the server
        """
        now = int(time.time())
        self.session_tracker[session_id] = {'c':1, 't': now}
