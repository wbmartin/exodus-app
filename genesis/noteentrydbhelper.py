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


class NoteEntryDBHelper(object):
    """
    Web user authentication database helper
    """

    def __init__(self, persistence):
        """ Class initialization """
        self.pers = persistence
        self.logger = logging.getLogger('app')

    def sel(self, security_context, req_note_entry_id):
        """
        retrieve a note_entry if exists
        """
        try:
            #Establish connection to persistence service
            nosqldb = self.pers.nosql_db
            self.logger.debug('securityContext' + security_context + ' ' + req_note_entry_id)
            result = nosqldb['noteEntries'].find_one(
                {
                    '_id': ObjectId(req_note_entry_id),
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
            result = nosqldb['noteEntries'].find(
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

    def ins(self, security_context, note_entry_req):
        """
        Insert a row
        """
        try:
            nosqldb = self.pers.nosql_db
            del note_entry_req['_id']
            note_entry_req['updateDate'] = datetime.datetime.utcnow()
            note_entry_req['createDate'] = datetime.datetime.utcnow()

            result = nosqldb['noteEntries'].insert_one(note_entry_req)
            note_entry_req['_id'] = result.inserted_id
            #self.logger.debug('update result: ' + dumps(result))
            return note_entry_req
        except Exception as exc:
            self.logger.debug('Unexpected Error %s', str(exc))
            raise

    def upd(self, security_context, note_entry_req):
        """
        Update a document
        """
        try:
            nosqldb = self.pers.nosql_db
            obj_id = ObjectId(note_entry_req['_id']['$oid'])
            note_entry_req['updateDate'] = datetime.datetime.utcnow()
            note_entry_req['_id'] = obj_id
            if 'createUser' in note_entry_req:
                del note_entry_req['createUser']
            if 'createDate' in note_entry_req:
                del note_entry_req['createDate']

            result = nosqldb['noteEntries'].update_one(
                {
                    '_id': note_entry_req['_id'],
                    'securityContext': security_context,
                },
                {
                    '$set':note_entry_req
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
            result = nosqldb['noteEntries'].delete_one(
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





    def is_valid_note_entry(self, test_obj, goal):
        """
        Sanity check for the object
        """
        result = ''
        try:
            allowed_keys = [
                '_id', 'label', 'body', 'tags', 'createDate', 'createUser',
                'updateDate', 'updateUser', 'securityContext', 'attachments',
            ]
            #block unauthorized Keys
            for key in test_obj:
                if key not in allowed_keys:
                    result += 'Unexpected Key - ' + key + '; '
                #self.recursive_sanitize(test_obj)

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
