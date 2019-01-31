# -*- coding: utf-8 -*-
"""
Original Source contributed by: https://github.com/loanzen/falcon-auth/
"""

from __future__ import absolute_import
from __future__ import division

import base64
from datetime import timedelta, datetime

import falcon
import jwt
import time
import logging
from jwt import InvalidTokenError

from falcon_auth.serializer import ExtendedJSONEncoder



class AuthBackend(object):
    """
    Base Class for all authentication backends. If successfully authenticated must
    return the authenticated `user` object. In case authorization header is
    not set properly or there is a credential mismatch, results in an
    `falcon.HTTPUnauthoried exception` with proper description of the issue

    Args:
        user_loader(function, required): A callback function that is called with the
            decoded `token` extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.

        auth_header_prefix(string, optional): A prefix that is used with the
            bases64 encoded credentials in the `Authorization` header.

    """

    def __init__(self, user_loader, auth_header_prefix='basic'):
        raise NotImplementedError("Must be overridden")

    def parse_auth_token_from_request(self, auth_header):
        """
        Parses and returns Auth token from the request header. Raises
        `falcon.HTTPUnauthoried exception` with proper error message
        """

        if not auth_header:
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description='Missing Authorization Header',
                challenges=None)

        parts = auth_header.split()

        if parts[0].lower() != self.auth_header_prefix.lower():
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description='Invalid Authorization Header: '
                            'Must start with {0}'.format(self.auth_header_prefix),
                challenges=None)

        elif len(parts) == 1:
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description='Invalid Authorization Header: Token Missing',
                challenges=None)
        elif len(parts) > 2:
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description='Invalid Authorization Header: Contains extra content',
                challenges=None)

        return parts[1]

    def authenticate(self, req, resp, resource):
        """
        Authenticate the request and return the authenticated user. Must return
        `None` if authentication fails, or raise an exception

        """
        raise NotImplementedError(".authenticate() must be overridden.")

    def get_auth_token(self, user_payload):
        """
        Returns a authentication token created using the provided user details

        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        raise NotImplementedError("Must be overridden")

    def get_auth_header(self, user_payload):
        """
        Returns the value for authorization header
        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        auth_token = self.get_auth_token(user_payload)
        return '{auth_header_prefix} {auth_token}'.format(
            auth_header_prefix=self.auth_header_prefix, auth_token=auth_token
        )


class JWTAuthBackend(AuthBackend):
    """
    Token based authentication using the `JSON Web Token standard <https://jwt.io/introduction/>`__
    Clients should authenticate by passing the token key in the `Authorization`
    HTTP header, prepended with the string specified in the setting
    `auth_header_prefix`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj

    Args:
        user_loader(function, required): A callback function that is called with the
            decoded `jwt payload` extracted from the `Authorization`
            header. Returns an `authenticated user` if user exists matching the
            credentials or return `None` to indicate if no user found or credentials
            mismatch.

        secrey_key(string, required): A secure key that was used to encode and
            create the `jwt token` from a dictionary payload

        algorithm(string, optional): Specifies the algorithm that was used
            to for cryptographic signing. Default is ``HS256`` which stands for
            HMAC using SHA-256 hash algorithm. Other supported algorithms can be
            found `here <http://pyjwt.readthedocs.io/en/latest/algorithms.html>`__

        auth_header_prefix(string, optional): A prefix that is used with the
            bases64 encoded credentials in the `Authorization` header. Default is
            ``jwt``

        leeway(int, optional): Specifies the timedelta in seconds that is allowed
            as leeway while validating `expiration time` / `nbf(not before) claim`
            /`iat (issued at) claim` which is in past but not very
            far. For example, if you have a JWT payload with an expiration time
            set to 30 seconds after creation but you know that sometimes you will
            process it after 30 seconds, you can set a leeway of 10 seconds in
            order to have some margin. Default is ``0 seconds``

        expiration_delta(int, optional): Specifies the timedelta in seconds that
            will be added to current time to set the expiration for the token.
            Default is ``1 day(24 * 60 * 60 seconds)``

        audience(string, optional): Specifies the string that will be specified
            as value of ``aud`` field in the jwt payload. It will also be checked
            agains the ``aud`` field while decoding.
            
        issuer(string, optional): Specifies the string that will be specified
            as value of ``iss`` field in the jwt payload. It will also be checked
            agains the ``iss`` field while decoding.

    """

    def __init__(self, user_loader, secret_key,
                 algorithm='HS256', auth_header_prefix='jwt',
                 leeway=0, expiration_delta=24 * 60 * 60,
                 audience=None, issuer=None,
                 verify_claims=None, required_claims=None,
                 cfg=None, session_manager=None):

        self.user_loader = user_loader
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.leeway = timedelta(seconds=leeway)
        self.auth_header_prefix = auth_header_prefix
        self.expiration_delta = timedelta(seconds=expiration_delta)
        self.audience = audience
        self.issuer = issuer
        self.logger = logging.getLogger('app')
        self.verify_claims = verify_claims or \
                                ['signature', 'exp', 'nbf', 'iat']
        self.required_claims = required_claims or ['exp', 'iat', 'nbf']

        if 'aud' in self.verify_claims and not audience:
            raise ValueError('Audience parameter must be provided if '
                             '`aud` claim needs to be verified')

        if 'iss' in self.verify_claims and not issuer:
            raise ValueError('Issuer parameter must be provided if '
                             '`iss` claim needs to be verified')
        self.cfg = cfg
        self.session_manager = session_manager  


    def _decode_jwt_token(self, req):

        # Decodes the jwt token into a payload
        #auth_header = req.get_header('Authorization')
        auth_header = 'jwt ' + req.cookies[self.auth_header_prefix]
        token = self.parse_auth_token_from_request(auth_header=auth_header)

        options = dict(('verify_' + claim, True) for claim in self.verify_claims)

        options.update(
            dict(('require_' + claim, True) for claim in self.required_claims)
        )

        try:

            payload = jwt.decode(jwt=token, key=self.secret_key,
                                 options=options,
                                 algorithms=[self.algorithm],
                                 issuer=self.issuer,
                                 audience=self.audience,
                                 leeway=self.leeway)
        except InvalidTokenError as ex:
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description=str(ex),
                challenges=None)

        return payload

    def authenticate(self, req, resp, resource):
        """
        Extract auth token from request `authorization` header,  deocode jwt token,
        verify configured claims and return either a ``user``
        object if successful else raise an `falcon.HTTPUnauthoried exception`
        """
        payload = self._decode_jwt_token(req)
        user = self.user_loader(payload)
        if not user:
            raise falcon.HTTPUnauthorized(
                title='401 Unauthorized',
                description='Invalid JWT Credentials',
                challenges=None)
            
        
        #self.logger.debug("now %s - ses %s - tm %s", now, user['ses'],self.session_renew_window )
        #FalconHelper watches for IP addresses exceeding RPM and adds 'ANTI-AUTO' into the 
        #request context if detected.  It will also reset the count.  Once this flag is set
        # a user profile variable 'AA' will be set and signed in the JWT.
        #The only way to clear it is to answer the captcha
        # Tipping Request 
        
        self.session_manager.check_auth_session(req, resp, user['user']['ses'])
        now = int(time.time())
        if now - user['sestm']  > self.cfg.SESSION_RENEW_WINDOW:
            #reset the ses timer with current time and prepare the cookie swap
            jwt_payload = self.get_auth_token(user_payload=user['user'])
            # set the new cookie
            resp.set_cookie(
                'jwt',
                jwt_payload,
                secure=self.cfg.REQUIRE_SECURE_COOKIES,
                http_only=True,
                path="/",
                domain=self.cfg.COOKIE_DOMAIN
            )
            
        
        return user

    def get_auth_token(self, user_payload):
        """
        Create a JWT authentication token from ``user_payload``

        Args:
            user_payload(dict, required): A `dict` containing required information
                to create authentication token
        """
        self.logger.debug("getting new auth token")
        now = datetime.utcnow()
        payload = {
            'user': user_payload,
            'sestm': int(time.time())
        }
        if 'iat' in self.verify_claims:
            payload['iat'] = now

        if 'nbf' in self.verify_claims:
            payload['nbf'] = now + self.leeway

        if 'exp' in self.verify_claims:
            payload['exp'] = now + self.expiration_delta
            
        return jwt.encode(payload, self.secret_key,
                          json_encoder=ExtendedJSONEncoder).decode('utf-8')


