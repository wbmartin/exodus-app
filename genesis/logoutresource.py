"""
Authentication Resource for falcon framework authentication

"""
#Standard Libraries
import logging


#3rd Party Libraries


#Local app libraries




class LogoutResource(object):
    """
    provides logout functionality
    """
    def __init__(self, session_manager, cfg, web_util):
        """
        Initialization function
        """
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.cfg = cfg
        #self.persistence = persistence
        self.web_util = web_util
        self.session_manager = session_manager
    
    def on_get(self, req, resp, csrf):
        """
        Processes Get Request to logout, requires csrf token in url
        """
        user_token = req.context['user']['user']
        if self.web_util.check_csrf(user_token['ses'], csrf):
            self.logger.debug(
                'Ending session %s for user %s',
                user_token['username'],
                user_token['ses']
            )
            resp.set_cookie(
                'jwt',
                '',
                secure=self.cfg.REQUIRE_SECURE_COOKIES,
                http_only=True,
                path="/",
                domain=self.cfg.COOKIE_DOMAIN
            )
            self.session_manager.end_session(user_token['ses'])
      
        