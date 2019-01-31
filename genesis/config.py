"""
    Basic configurations settings for the application
"""
import os
import logging

class Config(object):
    """
    Configuration options used throughout the app
    """

    def get_os_var(self, var_name):
        """
        Retrieve configurations from environmental variables
        """
        try:
            var_val = os.environ[var_name]
            if var_val == "":
                raise ValueError("Empty OS Variable: " + var_name)
            return var_val
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def __init__(self):
        self.logger = logging.getLogger('app')
        self.app_short_name = self.get_os_var('ENV_CFG_APP_SHORT_NAME')
        self.app_long_name = self.get_os_var('ENV_CFG_APP_LONG_NAME')
        # Connect to the NoSQL DB
        self.enable_nosql_db = self.get_os_var('ENV_CFG_ENABLE_NOSQL_DB') == 'True'

        # NOSSQL Database configuration Options if needed.
        # pylint: disable=invalid-name
        self.NOSQL_DB = {
            "user": self.get_os_var('ENV_SEC_NOSQL_DB_USERNAME'),
            "pass": self.get_os_var('ENV_SEC_NOSQL_DB_PASSWORD'),
            "ip": self.get_os_var('ENV_CFG_NOSQL_DB_IP'),
            "name": self.get_os_var('ENV_CFG_NOSQL_DB_NAME')
            }

        #  Connect to the SQL DB
        self.ENABLE_SQL_DB = self.get_os_var('ENV_CFG_ENABLE_SQL_DB') == 'True'

        #Configuration options for the SQL Database
        self.SQL_DB = {
            "user": self.get_os_var('ENV_SEC_SQL_DB_USERNAME'),
            "host": self.get_os_var('ENV_CFG_SQL_DB_HOST'),
            "passwd": self.get_os_var('ENV_SEC_SQL_DB_PASSWORD'),
            "dbname": self.get_os_var('ENV_CFG_SQL_DB_DBNAME')
            }

        #Python application level configurations
        self.APP = {
            "host": self.get_os_var('ENV_CFG_APP_HOST'),
            "port": self.get_os_var('ENV_CFG_APP_PORT'),
            "jwt_secret_key": self.get_os_var('ENV_SEC_APP_JWT_SECRET_KEY'),
            "jwt_max": int(self.get_os_var('ENV_CFG_APP_JWT_MAX'))
        }

        # Permits anonymous user creation when enabled.
        self.PERMIT_ANON_USER_CREATE = self.get_os_var('ENV_CFG_PERMIT_ANON_USER_CREATE') == 'True'

        #Require Secure Cookies (Dev environment expected to be False)
        self.REQUIRE_SECURE_COOKIES = self.get_os_var('ENV_CFG_REQUIRE_SECURE_COOKIES') == 'True'

        #Basic GUnicorn Configuration
        self.GUNICORN = {
            'loglevel': self.get_os_var('ENV_CFG_GUNICORN_LOGLEVEL'),
            'errorlog': self.get_os_var('ENV_CFG_GUNICORN_ERRORLOG'),
            'capture_output': self.get_os_var('ENV_CFG_GUNICORN_CAPTURE_OUTPUT') == 'True',
            'enable_stdio_inheritance': self.get_os_var('ENV_CFG_GUNICORN_ENABLE_STDIO_INHERITANCE') == 'True', #pylint: disable=line-too-long
            'workers': self.get_os_var('ENV_CFG_GUNICORN_WORKERS'),
            'bind': self.get_os_var('ENV_CFG_GUNICORN_BIND'),

        }

        #Full Path to configuration file for Logger, JSON config format expected
        self.LOGGING_CONFIG_FILE = self.get_os_var('ENV_CFG_LOGGING_CONFIG_FILE')
        self.MAX_UNAUTH_SESSION_DURATION = int(self.get_os_var('ENV_CFG_MAX_UNAUTH_SESSION_DURATION'))#pylint: disable=line-too-long
        self.SESSION_RENEW_WINDOW = int(self.get_os_var('ENV_CFG_SESSION_RENEW_WINDOW'))
        self.COOKIE_DOMAIN = self.get_os_var('ENV_CFG_COOKIE_DOMAIN')
        # Maximum Requests per minute for an IP Address
        self.MAX_RPM = int(self.get_os_var('ENV_CFG_MAX_RPM'))
        # Max Number of more RPM's before the app starts sends 401
        self.MAX_RPM_GRACE = int(self.get_os_var('ENV_CFG_MAX_RPM_GRACE'))
        self.ANTIAUTOMATION_EXEMPT_IPS = self.get_os_var('ENV_CFG_ANTIAUTOMATION_EXEMPT_IPS').split('|') #pylint: disable=line-too-long
        self.PATH_PREFIX = self.get_os_var('ENV_CFG_PATH_PREFIX')
        self.EMAIL_SERVICE_ACCOUNT_NAME = self.get_os_var('ENV_SEC_EMAIL_SERVICE_ACCOUNT_NAME')
        self.EMAIL_SERVICE_ACCOUNT_PASSWORD = self.get_os_var('ENV_SEC_EMAIL_SERVICE_ACCOUNT_PASSWORD')
        #CLIENT_APP_BASE_URL used for password resets
        self.CLIENT_APP_BASE_URL = self.get_os_var('ENV_CFG_CLIENT_APP_BASE_URL')
        self.FILE_STORE_PATH = self.get_os_var('ENV_CFG_FILE_STORE_PATH')
        self.GOOGLE_OAUTH_CLIENT_ID = self.get_os_var('ENV_SEC_GOOGLE_OAUTH_CLIENT_ID') #pylint: disable=line-too-long

        self.ENV_CFG_CLIENT_AWS_S3_BUCKET_NAME = self.get_os_var('ENV_CFG_CLIENT_AWS_S3_BUCKET_NAME') #pylint: disable=line-too-long
        self.ENV_CFG_CLIENT_AWS_REGION = self.get_os_var('ENV_CFG_CLIENT_AWS_REGION') #pylint: disable=line-too-long
        self.ENV_CFG_CLIENT_AWS_COGNITO_IDENTITY_POOL_ID= self.get_os_var('ENV_CFG_CLIENT_AWS_COGNITO_IDENTITY_POOL_ID') #pylint: disable=line-too-long

        self.GCP_CS_BUCKET_NAME = self.get_os_var('ENV_CFG_GCP_CS_BUCKET_NAME')
        self.GCP_PROJECT_NAME = self.get_os_var('ENV_CFG_GCP_PROJECT_NAME')
        self.GCP_CS_ENCRTYPION_KEY = self.get_os_var('ENV_SEC_GCP_CS_ENCRTYPION_KEY')
