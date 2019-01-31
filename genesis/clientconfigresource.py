"""
ClientConfig Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps

#App specific libraries



class ClientConfigResource(object):
    """
    Falcon web request handlers for note_entrys
    """

    def __init__(self, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.cfg = cfg
        self.web_util = web_util


    def on_get(self, req, resp, security_context='', ):
        """
        Handles GET requests - returns Client runtime config
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            self.web_util.check_grant(security_context, user_token, 'GET_CLIENT_CONFIG')

            resp.body = dumps(
              {
                'AWS_S3_BucketName': self.cfg.ENV_CFG_CLIENT_AWS_S3_BUCKET_NAME,
                'AWS_Region': self.cfg.ENV_CFG_CLIENT_AWS_REGION,
                'AWS_Cognito_IdentiyPoolId': self.cfg.ENV_CFG_CLIENT_AWS_COGNITO_IDENTITY_POOL_ID,
              }
            )

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
