"""
Persistence interface for Authentication
"""
#Standard Libraries
import logging
import json
import uuid
import datetime
import re
#import time


#3rd Party Libraries
import bcrypt
from bson import ObjectId
from bson.json_util import dumps
from pymongo.errors import DuplicateKeyError




class UserDBHelper(object):
    """
    Web user authentication database helper
    """
    def __init__(self, persistence):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')

    def sel(self, security_context, req_user_id):
        """
        retrieve a user if exists
        """
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            self.logger.debug('secuirityContext' + security_context + ' ' + req_user_id)
            result = nosqldb['users'].find_one(
                {
                    '_id': ObjectId(req_user_id),
                    # 'security_context': security_context
                },
                {
                    'passwdHash': False
                }
            )
            self.pers.nosql_conn.close()
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error 001: %s', str(exc))
            raise
    def sel_by_email(self, security_context, email):
        """
        retrieve a user if exists
        """
        self.logger.debug("sel_by_email running")
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            self.logger.debug('securityContext:' + security_context + ' ' + email)
            result = nosqldb['users'].find(
                {
                    'email': email,
                    'securityContext': security_context
                },
                {
                    'passwdHash': False
                }
            )
            self.pers.nosql_conn.close()
            return list(result)
        except TypeError as exc:
            self.logger.debug('Unexpected Error 002: ')
        except Exception as exc:
            self.logger.debug('Unexpected Error 003: %s', str(exc))
            raise


    def sel_list(self, security_context):
        """
        retrieve the full list of users.
        """
        try:
            nosqldb = self.pers.nosql_db
            #result_list = []
            result = nosqldb['users'].find(
                {
                    'securityContext': security_context
                },
                {
                    'passwdHash': False
                }
            )
            return list(result)
        except Exception as exc:
            self.logger.debug('Unexpected Error 004: %s', str(exc))
            raise

    def ins(self, user_req):
        """
        Insert a row
        """
        try:
            nosqldb = self.pers.nosql_db
            del user_req['_id']
            user_req['updateDate'] = datetime.datetime.utcnow()
            user_req['createDate'] = datetime.datetime.utcnow()
            if 'userGroups' not in user_req:
                user_req['userGroups'] = []

            result = nosqldb.users.insert_one(user_req)
            user_req['_id'] = result.inserted_id

            #self.logger.debug('update result: ' + dumps(result))
            return user_req
        except DuplicateKeyError:
            self.logger.debug('Duplicate User Attempt')
            return 'DUP'
        except Exception as exc:
            self.logger.debug('Unexpected Error 005: %s', str(exc))
            raise

    def upd(self, security_context, user_req):
        """
        Update a document
        """
        self.logger.debug('userdbhelper - upd running')
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(user_req['_id']['$oid'])
            user_req['updateDate'] = datetime.datetime.utcnow()
            user_req['_id'] = obj_id
            if 'createUser' in user_req:
                del user_req['createUser']
            if 'createDate' in user_req:
                del user_req['createDate']

            result = nosqldb.users.update_one(
                {'_id': user_req['_id']},
                {'$set':user_req},
                upsert=False)
            if result.modified_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #sterilize the result, causes problems with bson.dumps and encoding
            result = {
                'modified_count': result.modified_count
            }
            #self.logger.debug('update result: ' + dumps(result))
            return result
        except DuplicateKeyError:
            self.logger.debug('Duplicate User Attempt')
            return 'DUP'
        except Exception as exc:
            self.logger.debug('Unexpected Error 006: %s', str(exc))
            raise


    def drp(self, security_context, user_id):
        """
        remove a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(user_id)
            result = nosqldb.users.delete_one({'_id': obj_id})
            if result.deleted_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #self.logger.debug('update result: ' + dumps(result))
            return
        except Exception as exc:
            self.logger.debug('Unexpected Error 007: %s', str(exc))
            raise

    def is_valid_user(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:

            allowed_keys = [
                '_id', 'username', 'securityContext', 'createDate', 'createUser',
                'updateDate', 'updateUser', 'passwdHash', 'userGroups',
                'userGrants', 'userNotes', 'email'
            ]
            #block unauthorized Keys
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursiveSanitize(test_obj)

            if 'username' not in test_obj:
                result += 'Missing username; '
            if 'securityContext' not in test_obj:
                result += 'Missing securityContext; '
            if 'email' not in test_obj:
                result += 'Missing Email; '
            #if 'passwdHash' not in test_obj and goal == 'INS':
            #    result += 'Missing passwdHash; '
            if '_id' not in test_obj:
                result += 'Missing _id; '

            if result == '': #required field present, check integrity
                if len(test_obj['username']) > 50:
                    result += 'Username > 50 chars;'
                if len(test_obj['email']) > 75:
                    result += 'email > 75 chars;'
                if not re.match(r'[^@]+@[^@]+\.[^@]+', test_obj['email']):
                    result += 'invalid email format'
                if goal == 'INS' and len(test_obj['passwdHash']) > 150:
                    result += 'passwdHash > 150 chars;'
                if goal == 'INS' and str(test_obj['_id']) != '0':
                    result += '_id must be 0 on insert' + test_obj['_id']
            if result == '':
                result = 'OK'
            return result
        except Exception as exc: #pylint: disable=broad-except
            self.logger.debug('Unexpected Error 008: %s', str(exc))
            raise
            #return 'Unexpected Validation Error'

    def authenticate_user(self, username, passwd):
        """
        retrieve user and grants if exists
        """
        hashed_pwd_from_db = ''
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            db_record = nosqldb['users'].find({'username': username})
            user_profile = {}
            #Sanity Check the output
            if not db_record:
                user_profile = "DENIED - No Such User"
                self.logger.debug(
                    "web user auth attempt:%s|%s",
                    user_profile,
                    username
                    )
            elif db_record.count() > 1:
                user_profile = "DENIED - Credentials Failed"
                self.logger.debug(
                    "web user auth attempt: %s|%s",
                    user_profile,
                    username
                    )
            else:
                #NB - The password has to be brought back from the
                # database because of the salt
                self.logger.debug("testing hash from db")
                hashed_pwd_from_db = db_record[0]['passwdHash']

                if bcrypt.checkpw(passwd.encode('utf-8'), hashed_pwd_from_db):
                #if str(hashed_pwd_from_web) == str(hashed_pwd_from_db):
                #if bcrypt.checkpw(hashed_pwd_from_db, hashed_pwd_from_web):
                    self.logger.debug('passwords match')
                    user_profile = self.post_authentication_processing(db_record[0])
                else:
                    self.logger.debug('Passwords do not match')
                    user_profile = None

            del hashed_pwd_from_db
            del passwd
            del db_record
            self.pers.nosql_conn.close()
            return user_profile
        except Exception as exc: #pylint: disable=broad-except
            self.logger.error('Unexpected Error 275: %s', str(exc))
            return 'Unexpected Validation Error'


    def post_authentication_processing(self, user_result):
        """
        Load grants, etc after authenticated
        """
        try:
            nosqldb = self.pers.nosql_db
            user_group_grants = user_result['userGrants']
            for user_group in user_result['userGroups']:
                self.logger.debug('adding group %s', user_group)
                new_grants = nosqldb['userGroups'].find_one({'groupRoleName': user_group})
                if new_grants:
                    self.logger.debug('new_grantsX' + dumps(new_grants))
                    for (key) in new_grants['privilegeGrants']:
                        self.logger.debug('new_grants' + key + " " )
                        if key in user_group_grants:
                            user_group_grants[key] = user_group_grants[key] + new_grants['privilegeGrants'][key]
                        else:
                            user_group_grants[key] = new_grants['privilegeGrants'][key]
            user_profile = {
                'username': user_result['username'],
                'grants': user_group_grants,
                'ses': str(uuid.uuid4())
            }
            self.logger.debug("post_authetication_processing yielded: %s",
                              str(user_profile))
            return user_profile
        except Exception as exc: #pylint: disable=broad-except
            self.logger.error('Unexpected Error 276: %s', str(exc))
            raise



    def set_user_grants(self, username, grants):
        """ Update the privileges assigned to a user """
        #TODO Create tests for this function
        #TODO Migrate to nosqld
        try:
            connection = self.pers.sql_db_engine.connect()
            users_table = self.pers.sql_meta.tables["t_users"]
            upd = users_table.update()
            grants_s = json.dumps(grants)
            result = connection.execute(upd, username=username, user_grants=grants_s)
            result.close()
            connection.close()
            return "USER_CREATED"
        except Exception as exc: #pylint: disable=broad-except
            self.logger.debug('Unexpected Error 010: %s', str(exc))
            return "Unexpected User Creation Error"
