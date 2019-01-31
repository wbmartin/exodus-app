"""
Persistence interface for Authentication
"""
#Standard Libraries
import logging
import datetime
#import time


#3rd Party Libraries
from bson import ObjectId



class SecurityContextDBHelper(object):
    """
    Web Security Context database helper
    """
    def __init__(self, persistence):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')

    def sel(self, security_context, req_security_context_id):
        """
        retrieve a user if exists
        """
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db

            result = nosqldb['securityContexts'].find_one(
                {
                    '_id': ObjectId(req_security_context_id),
                    'securityContext': security_context,
                }
            )
            self.pers.nosql_conn.close()
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def sel_list(self, security_context):
        """
        retrieve the full list of SecurityContexts.
        """
        try:
            nosqldb = self.pers.nosql_db
            result = nosqldb['securityContexts'].find({
                'securityContext': security_context,
            })
            self.logger.debug('Result Count %s', str(result.count()))
            #result.close()
            #self.pers.nosql_conn.close()
            return list(result)
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def ins(self, security_context, security_context_req):
        """
        Insert a row
        """
        try:
            nosqldb = self.pers.nosql_db
            del security_context_req['_id']
            security_context_req['updateDate'] = datetime.datetime.utcnow()
            security_context_req['createDate'] = datetime.datetime.utcnow()

            result = nosqldb['securityContexts'].insert_one(security_context_req)
            security_context_req['_id'] = result.inserted_id
            #self.logger.debug('update result: ' + dumps(result))
            return security_context_req
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def upd(self, security_context, security_context_req):
        """
        Update String
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(security_context_req['_id']['$oid'])
            security_context_req['updateDate'] = datetime.datetime.utcnow()
            security_context_req['_id'] = obj_id
            del security_context_req['createUser']
            del security_context_req['createDate']

            result = nosqldb['securityContexts'].update_one(
                {'_id': security_context_req['_id']},
                {'$set':security_context_req},
                upsert=False
                )
            if result.modified_count != 1:
                self.logger.debug('Update security_context Failed to find a match')
            #sterilize the result, causes problems with bson.dumps and encoding
            result = {
                'modified_count': result.modified_count
            }
            #self.logger.debug('update result: ' + dumps(result))
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def drp(self, security_context, security_context_id):
        """
        Delete a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(security_context_id)
            result = nosqldb['securityContexts'].delete_one({'_id': obj_id})
            if result.deleted_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #self.logger.debug('update result: ' + dumps(result))
            return
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise





    def is_valid_security_context(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:
            allowed_keys = [
                '_id', 'shortName', 'longName', 'note', 'createDate',
                'createUser', 'updateDate', 'updateUser', 'securityContext'
            ]
            #block unauthorized Keys
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursiveSanitize(test_obj)

            if 'shortName' not in test_obj:
                result += 'Missing short name; '
            if 'longName' not in test_obj:
                result += 'Missing Long Name; '

            if '_id' not in test_obj:
                result += 'Missing _id; '

            if result == '': #required field present, check integrity
                if len(test_obj['shortName']) > 10:
                    result += 'shortName > 10 chars;'
                if goal == 'INS' and test_obj['_id'] != '0':
                    result += '_id must be 0 on insert' + test_obj['_id']
            if result == '':
                result = 'OK'
            return result
        except Exception as exc: #pylint: disable=broad-except
            self.logger.debug('Unexpected Error %s ', str(exc))
            return 'Unexpected validation error'
