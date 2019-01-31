"""
Persistence interface for Authentication
"""
#Standard Libraries
import logging
import datetime
#import time

#3rd Party Libraries
from bson import ObjectId
#from genesis.util import recursive_sanitize


class FileStoreDBHelper(object):
    """
    Web user authentication database helper
    """

    def __init__(self, persistence):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')

    def sel(self, security_context, req_file_store_id):
        """
        retrieve a file if exists
        """
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            self.logger.debug('securityContext' + security_context + ' ' + req_file_store_id)
            result = nosqldb['fileStore'].find_one(
                {
                    '_id': ObjectId(req_file_store_id),
                    'securityContext': security_context
                }
            )
            self.pers.nosql_conn.close()
            return result
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def ins(self, security_context, file_store_req):
        """
        Insert a row
        """
        try:
            nosqldb = self.pers.nosql_db
            del file_store_req['_id']
            file_store_req['updateDate'] = datetime.datetime.utcnow()
            file_store_req['createDate'] = datetime.datetime.utcnow()

            result = nosqldb['fileStore'].insert_one(file_store_req)
            file_store_req['_id'] = result.inserted_id
            #self.logger.debug('update result: ' + dumps(result))
            return file_store_req
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def upd(self, security_context, file_store_req):
        """
        Update a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(file_store_req['_id']['$oid'])
            file_store_req['updateDate'] = datetime.datetime.utcnow()
            file_store_req['_id'] = obj_id
            del file_store_req['createUser']
            del file_store_req['createDate']

            result = nosqldb['fileStore'].update_one(
                {
                    '_id': file_store_req['_id'],
                    'securityContext': security_context,
                },
                {
                    '$set':file_store_req
                },
                upsert=False
            )
            if result.modified_count != 1:
                self.logger.debug('Update User Failed to find a match')

            #sterilize the result, causes problems with bson.dumps and encoding
            result = {
                'modified_count': result.modified_count
            }
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
            result = nosqldb['fileStore'].delete_one(
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





    def is_valid_file_store(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:
            allowed_keys = [
                '_id', 'fileName', 'fileSize', 'tags', 'contentType',
                'logicalPath', 'createDate', 'createUser',
                'updateDate', 'updateUser', 'securityContext', 'cloudId'
            ]
            #block unauthorized Keys
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursive_sanitize(test_obj)

            if 'fileName' not in test_obj:
                result += 'Missing file name; '
            if 'fileSize' not in test_obj:
                result += 'Missing file size; '
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
