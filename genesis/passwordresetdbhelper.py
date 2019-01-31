"""
Persistence interface for Password Resets
"""
#Standard Libraries
import logging
import datetime
import secrets
#import time

#3rd Party Libraries



class PasswordResetDBHelper(object):
    """
    Web user authentication database helper
    """

    def __init__(self, persistence, cfg):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')
        self.cfg = cfg

    def create_password_reset_token(self, user_id):
        """
        Initiate a password reset with a complex token, multi step
        """
        try:
            self.logger.debug('Password Reset attempt %s', user_id)
            password_reset_token = ''
            nosqldb = self.pers.nosql_db
            db_user_record = nosqldb['users'].find_one(
                {
                    '$or': [
                        {'username': user_id},
                        {'email': user_id}
                    ]
                }
            )
            # Confirm the user exists from previous query
            if db_user_record:
                # purge any old requests, even if unrelated
                nosqldb['passwordResets'].delete_many(
                    {
                        'requestDate': {'$lt': datetime.datetime.utcnow() -
                                               datetime.timedelta(minutes=5)}
                    }
                )

                already_sent = nosqldb['passwordResets'].find_one(
                    {
                        'email': user_id
                    }
                )
                if not already_sent:
                    # create a password reset token
                    #password_reset_token = hashlib.sha512('abc'.encode('utf-8')).hexdigest()
                    password_reset_token = secrets.token_urlsafe(255)
                    #persist the password reset request
                    nosqldb['passwordResets'].insert_one(
                        {
                            'username': db_user_record['username'],
                            'email': db_user_record['email'],
                            'requestDate': datetime.datetime.utcnow(),
                            'resetToken': password_reset_token,
                        }
                    )
                else:
                    self.logger.debug('Password Reset Email Denied: existing request in flight')
            return password_reset_token
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise


    def change_password(self, reset_token, new_password_hash):
        """
        2nd phase of a password reset
        """
        try:
            self.logger.debug('change_password running')
            nosqldb = self.pers.nosql_db
            reset_request = nosqldb['passwordResets'].find_one(
                {'resetToken': reset_token}
            )

            if reset_request:
                self.logger.debug('reset request match')
                nosqldb['users'].update_one(
                    {
                        'username': reset_request['username']
                    },
                    {
                        '$set': {'passwdHash': new_password_hash}
                    }


                )
            else:
                self.logger.debug('reset request mismatch, nothing changed')
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise


    def is_valid_password_reset_request(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:
            allowed_keys = [
                'passwd', 'resetToken', 'username', 'email'
            ]
            #block unauthorized Keys
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursiveSanitize(test_obj)

            if 'body' not in test_obj:
                result += 'Missing body field; '
            if 'label' not in test_obj:
                result += 'Missing label; '
            if 'securityContext' not in test_obj:
                result += 'Missing securityContext; '

            if result == '': #required field present, check integrity
                if len(test_obj['body']) > 500:
                    result += 'Note too long'
                if not isinstance(test_obj['securityContext'], str):
                    result += 'Secuirity Context is not a string;'

            if result == '':
                result = 'OK'
            return result
        except Exception as exc: #pylint: disable=broad-except
            self.logger.debug('Unexpected Error %s', str(exc))
            return 'Unexpected Validation Error'
