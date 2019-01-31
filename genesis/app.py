#app.py
""" app.py
Houses the application primary class
"""
#Standard Libraries
import logging
import falcon

#3rd Party Libraries
from pymongo import MongoClient
from sqlalchemy import create_engine
from sqlalchemy import MetaData


from falcon_multipart.middleware import MultipartMiddleware
from falconauth.backends import JWTAuthBackend
from falconauth.middleware import FalconAuthMiddleware

#Local app libraries
from genesis.falconhelpercomponent import FalconHelperComponent
from genesis.authresource import AuthResource
from genesis.usergrantresource import UserGrantResource
from genesis.logoutresource import LogoutResource
from genesis.anonnewuserresource import AnonNewUserResource
from genesis.persistence import Persistence
from genesis.webutil import WebUtil
from genesis.sessionmanager import SessionManager
from genesis.userresource import UserResource
from genesis.usergroupresource import UserGroupResource
from genesis.securitycontextresource import SecurityContextResource
from genesis.appgrantresource import AppGrantResource
from genesis.noteentryresource import NoteEntryResource
from genesis.passwordresetresource import PasswordResetResource
from genesis.sessionrefreshresource import SessionRefreshResource
from genesis.fileuploadresource import FileUploadResource
from genesis.googleauthresource import GoogleAuthResource
from genesis.clientconfigresource import ClientConfigResource
from genesis.heartbeatresource import HeartBeatResource

class GenesisService(falcon.API):
    """ Application Service Class - establishes DB, Middleware and application routes """
    def __init__(self, cfg):
        self.cfg = cfg
        self.logger = logging.getLogger('app')
        self.persistence = Persistence()
        web_util = WebUtil(cfg)
        self.session_manager = SessionManager(cfg, web_util)

        #setup NOSQL DB
        if self.cfg.enable_nosql_db:
            self.logger.debug('Configuring NOSQL DB')
            self.persistence.nosql_conn = MongoClient(
                'mongodb://' + self.cfg.NOSQL_DB["ip"] + ':27017/'
            )
            self.persistence.nosql_db = self.persistence.nosql_conn[self.cfg.NOSQL_DB["name"]]

        #setup SQL DB connection
        if self.cfg.ENABLE_SQL_DB:
            sqldb_conn_str = 'mysql://{user}:{password}@{host}/{database}'.format(
                host=self.cfg.SQL_DB["host"],
                user=self.cfg.SQL_DB["user"],
                password=self.cfg.SQL_DB["passwd"],
                database=self.cfg.SQL_DB["dbname"]
                )
            self.persistence.sql_db_engine = create_engine(sqldb_conn_str)
            self.persistence.sql_meta = MetaData()
            self.persistence.sql_meta.reflect(bind=self.persistence.sql_db_engine)


        #Auth Middleware
        #
        #LAMBDA function to extract the user information from the request

        # pylint: disable=line-too-long
        user_loader = lambda client_submitted_jwt: client_submitted_jwt if len(client_submitted_jwt) < self.cfg.APP['jwt_max'] else ''

        #define the authentication backend mechanism
        webuser_auth_backend = JWTAuthBackend(
            user_loader,
            self.cfg.APP["jwt_secret_key"],
            algorithm='HS256',
            auth_header_prefix='jwt',
            leeway=0,
            expiration_delta=self.cfg.MAX_UNAUTH_SESSION_DURATION, #longest time without re-authenticating
            audience=None,
            issuer=None,
            verify_claims=None,
            required_claims=None,
            cfg=self.cfg,
            session_manager=self.session_manager
            )
        #/auth - user won't have a jwt token when attempting to auth
        #/newuser - should be exempt if users will create their own passwords
        exempt_routes = [
            self.cfg.PATH_PREFIX + '/v1/auth',
            self.cfg.PATH_PREFIX + '/v1/googleauth',
            self.cfg.PATH_PREFIX + '/v1/newuser',
            self.cfg.PATH_PREFIX + '/v1/passwordreset',
            '/',
        ]

        auth_middleware = FalconAuthMiddleware(
            webuser_auth_backend,
            exempt_routes=exempt_routes,
            )

        #Initilize falcon
        falcon_helper = FalconHelperComponent(exempt_routes, self.cfg, self.session_manager)
        super(GenesisService, self).__init__(
            middleware=[falcon_helper, auth_middleware, MultipartMiddleware()]
        )

        #Create Application routes
        self.add_route(
             '/',
            HeartBeatResource(

                )
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/auth',
            AuthResource(
                persistence=self.persistence,
                webuser_auth_backend=webuser_auth_backend,
                cfg=self.cfg,
                web_util=web_util,
                session_manager=self.session_manager
                )
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/googleauth',
            GoogleAuthResource(
                persistence=self.persistence,
                webuser_auth_backend=webuser_auth_backend,
                cfg=self.cfg,
                web_util=web_util,
                session_manager=self.session_manager
                )
            )
        #Remove this if anonymous user creation disallowed
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/newuser',
            AnonNewUserResource(
                persistence=self.persistence,
                cfg=self.cfg, web_util=web_util
                )
            )
        #User Listing
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/users/{security_context}',
            UserResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #User updates
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/users/{security_context}/{user_id}',
            UserResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #SecurityContext Listing
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/securitycontexts/{security_context}',
            SecurityContextResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #SecurityContext updates
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/securitycontexts/{security_context}/{security_context_id}/',
            SecurityContextResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #User Grants updates
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/user/grant/{security_context}/{user_id}',
            UserGrantResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #User Group Listing
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/usergroup/{security_context}',
            UserGroupResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #User Group updates
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/usergroup/{security_context}/{user_group_id}',
            UserGroupResource(
                persistence=self.persistence, web_util=web_util
                )
            )

        #App Grants Listing
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/appgrants/{security_context}',
            AppGrantResource(
                persistence=self.persistence, web_util=web_util
                )
            )
        #App Grants updates
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/appgrants/{security_context}/{app_grant_id}',
            AppGrantResource(
                persistence=self.persistence, web_util=web_util
                )
            )






        #logout
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/logout/{csrf}',
            LogoutResource(
                self.session_manager,
                cfg,
                web_util
                )
            )
        #Provide Run Time Client configuration to the client
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/clientconfig/{security_context}',
            ClientConfigResource(cfg=self.cfg, web_util=web_util)
            )


        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/noteentries/{security_context}/{note_entry_id}',
            NoteEntryResource(persistence=self.persistence, web_util=web_util)
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/noteentries/{security_context}',
            NoteEntryResource(persistence=self.persistence, web_util=web_util)
            )

        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/passwordreset/',
            PasswordResetResource(
                persistence=self.persistence,
                cfg=self.cfg,
                web_util=web_util
                )
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/sessionrefresh/{security_context}',
            SessionRefreshResource(
                persistence=self.persistence,
                cfg=self.cfg,
                web_util=web_util
                )
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/fileupload/{security_context}',
            FileUploadResource(
                persistence=self.persistence,
                cfg=self.cfg,
                web_util=web_util
                )
            )
        self.add_route(
            self.cfg.PATH_PREFIX + '/v1/fileupload/{security_context}/{file_store_id}',
            FileUploadResource(
                persistence=self.persistence,
                cfg=self.cfg,
                web_util=web_util
                )
            )


    def start(self):
        """
        A hook to when a Gunicorn worker calls run().
        """
        self.logger.debug("GUNICORN worker called run")

    def stop(self, signal):
        """
        A hook to when a Gunicorn worker starts shutting down.
        """
        self.logger.debug("GUNICORN worker shutting down")
        if self.cfg.enable_nosql_db:
            self.persistence.nosql_db.close()
        if self.cfg.enable_sql_db:
            self.persistence.sql_db_engine.dispose()
