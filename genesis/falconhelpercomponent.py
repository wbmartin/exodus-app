"""
Middleware
"""
#Standard Libraries
import logging


#3rd Party Libraries
import falcon



class FalconHelperComponent(object):
    """
    Falcon Helper middleware
    """
    def __init__(self, exempt_routes, cfg, session_manager):
        self.logger = logging.getLogger('app')
        self.exempt_routes = exempt_routes
        self.cfg = cfg
        self.session_manager = session_manager

    def process_request(self, req, resp):
        """
        Set Header options
        """
        self.logger.debug('FalconHelperComponent process_request Executing ' +
                          req.method + ' ' + req.relative_uri
                         )

        #self.logger.debug('headers:' + dumps(req.headers))

        if req.path in self.exempt_routes:
            self.session_manager.check_unauth_session(req, resp)
        if ('jwt' not in req.cookies
                and req.path not in self.exempt_routes):
            self.logger.debug('Throwing 401 Non Exempt route missing jwt cookie')
            raise falcon.HTTPError(
                falcon.HTTP_401, #Forbidden
                'Error',
                "Missing JWT token"
                )


    def process_response(self, req, resp, resource, params):
        """
        Set Header options
        """
        self.logger.debug('FalconHelperComponent process_response Executing')
        resp.set_header("x-frame-options", "SAMEORIGIN")
        resp.set_header("X-Content-Type-Options", "nosniff")
        resp.set_header("X-XSS-Protection", "1; mode=block")
        resp.set_header("Access-Control-Allow-Origin", "*")
        resp.set_header("Server", "N")
