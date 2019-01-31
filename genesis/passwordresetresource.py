"""
PasswordReset Web service
"""
#Standard Libraries
import logging
import traceback
import smtplib

#Third Party Libraries
import falcon

import bcrypt

#App specific libraries
from genesis.passwordresetdbhelper import PasswordResetDBHelper



class PasswordResetResource(object):
    """
    Falcon web request handlers for password reset requests
    """

    def __init__(self, persistence, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.cfg = cfg
        self.web_util = web_util


    def on_post(self, req, resp):
        """
        Handles GET requests - returns a password_reset object from DB
        """
        self.logger.debug('on_post running')

        try:
            password_reset_req = self.web_util.parse_json_body(req.stream.read())
            if 'resetToken' in password_reset_req:
                self.change_password(
                    password_reset_req['resetToken'],
                    password_reset_req['passwd']
                )

            else: #neet to initiate the reset token
                self.initiate_password_reset('w.brandon.martin@gmail.com')

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

    def initiate_password_reset(self, user_id):
        """
        Start the password reset process.
        """
        email_addr = user_id
        password_reset_dbhelper = PasswordResetDBHelper(self.pers, self.cfg)
        password_reset_token = password_reset_dbhelper.create_password_reset_token(user_id)
        password_reset_url = self.cfg.CLIENT_APP_BASE_URL + '/passwordreset/' + password_reset_token
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo()
        server.starttls()
        self.logger.error(
            "Email user/pass: %s/%s",
            self.cfg.EMAIL_SERVICE_ACCOUNT_NAME,
            self.cfg.EMAIL_SERVICE_ACCOUNT_PASSWORD

        )

        server.login(
            self.cfg.EMAIL_SERVICE_ACCOUNT_NAME,
            self.cfg.EMAIL_SERVICE_ACCOUNT_PASSWORD
            )
        msg_header = 'From: {frm}\nTo: {to}\nSubject: {subj}\n\n'.format(
            frm=self.cfg.EMAIL_SERVICE_ACCOUNT_NAME,
            to=email_addr,
            subj=self.cfg.app_short_name + ' Password Reset Request'
            )
        msg_body = 'Other body text <a href="' + password_reset_url + '">link</a>'

        server.sendmail(
            self.cfg.EMAIL_SERVICE_ACCOUNT_NAME,
            email_addr,
            (msg_header + msg_body)
            )
        server.quit()


    def change_password(self, reset_token, new_password):
        """
        complete password resets
        """
        password_reset_dbhelper = PasswordResetDBHelper(self.pers, self.cfg)
        
        password_hash = bcrypt.hashpw(
            str(new_password).encode('utf-8'), bcrypt.gensalt()
            )
        password_reset_dbhelper.change_password(reset_token, password_hash)
