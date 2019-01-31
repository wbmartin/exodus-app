"""
Persistence interface for User groups
"""
#Standard Libraries
import logging
import datetime
#import time

#3rd Party Libraries
from bson import ObjectId
#from genesis.util import recursive_sanitize


class UserGroupDBHelper(object):
    """
    Web user authentication database helper
    """

    def __init__(self, persistence):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')

    def sel(self, security_context, req_user_group_id):
        """
        retrieve a user_group if exists
        """
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            self.logger.debug('securityContext' + security_context + ' ' + req_user_group_id)
            result = nosqldb['userGroups'].find_one(
                {
                    '_id': ObjectId(req_user_group_id),
                    'securityContext': security_context
                }
            )
            self.pers.nosql_conn.close()
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def sel_list(self, security_context):
        """
        retrieve the full list of users.
        """
        try:
            nosqldb = self.pers.nosql_db
            result = nosqldb['userGroups'].find(
                {
                    'securityContext': security_context
                }
            )

            #result.close()
            #self.pers.nosql_conn.close()
            return list(result)
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def ins(self, security_context, user_group_req):
        """
        Insert a row
        """
        try:
            nosqldb = self.pers.nosql_db
            del user_group_req['_id']
            user_group_req['updateDate'] = datetime.datetime.utcnow()
            user_group_req['createDate'] = datetime.datetime.utcnow()

            result = nosqldb['userGroups'].insert_one(user_group_req)
            user_group_req['_id'] = result.inserted_id
            #self.logger.debug('update result: ' + dumps(result))
            return user_group_req
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def upd(self, security_context, user_group_req):
        """
        Update a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(user_group_req['_id']['$oid'])
            user_group_req['updateDate'] = datetime.datetime.utcnow()
            user_group_req['_id'] = obj_id
            if 'createUser' in user_group_req:
                del user_group_req['createUser']
            if 'createDate' in user_group_req:
                del user_group_req['createDate']

            result = nosqldb['userGroups'].update_one(
                {
                    '_id': user_group_req['_id'],
                    'securityContext': security_context,
                },
                {
                    '$set':user_group_req
                },
                upsert=False
            )
            if result.modified_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #sterilize the result, causes problems with bson.dumps and encoding
            result = nosqldb['userGroups'].find_one(
                {
                    '_id': user_group_req['_id'],
                    'securityContext': security_context,
                },
            )
            #self.logger.debug('update result: ' + dumps(result))
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def drp(self, security_context, user_id):
        """
        remove a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(user_id)
            result = nosqldb['userGroups'].delete_one(
                {
                    '_id': obj_id,
                    'securityContext': security_context
                }
            )
            if result.deleted_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #self.logger.debug('update result: ' + dumps(result))
            return
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise





    def is_valid_user_group(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:
            allowed_keys = [
                '_id', 'createDate', 'createUser',
                'updateDate', 'updateUser', 'securityContext',
                'groupRoleName', 'privilegeGrants', 'userGroupNotes',
            ]
            #block unauthorized Keys NA because of securityContext
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursive_sanitize(test_obj)

            if 'securityContext' not in test_obj:
                result += 'Missing securityContext; '

            if result == '': #required field present, check integrity
                if not isinstance(test_obj['securityContext'], str):
                    result += 'Security Context is not a string;'

            if result == '':
                result = 'OK'
            return result
        except Exception as exc: #pylint: disable=broad-except
            self.logger.debug('Unexpected Error %s', str(exc))
            return 'Unexpected Validation Error'
