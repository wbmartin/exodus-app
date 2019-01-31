"""
NoteEntry Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps

#App specific libraries
from genesis.noteentrydbhelper import NoteEntryDBHelper


class NoteEntryResource(object):
    """
    Falcon web request handlers for note_entrys
    """

    def __init__(self, persistence, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util


    def on_get(self, req, resp, security_context='', note_entry_id=''):
        """
        Handles GET requests - returns a note_entry object from DB
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if note_entry is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'SEL_NOTE_ENTRY')


            #Initialize Database components
            note_entry_helper = NoteEntryDBHelper(self.pers)
            if note_entry_id != '':
                self.logger.debug('searching for %s', note_entry_id)
                note_entry = note_entry_helper.sel(security_context, note_entry_id)
                self.logger.debug('found %s', dumps(note_entry))
            else:
                note_entry = note_entry_helper.sel_list(security_context)
                self.logger.debug('Result Count %s', str(len(note_entry)))
            resp.body = dumps(note_entry)

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


    def on_post(self, req, resp, security_context):
        """
        Handles POST requests - Inserts a note_entry
        """
        self.logger.debug('on_post running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            note_entry_req = self.web_util.parse_json_body(req.stream.read())
            self.logger.debug('Posted Data: %s', dumps(note_entry_req))

            #Guard against CSRF
            self.web_util.check_csrf(user_token['ses'], req.headers)

            self.web_util.check_grant(security_context, user_token, 'INS_NOTE_ENTRY')

            #override any hijinks
            note_entry_req['createUser'] = user_token['username']
            note_entry_req['updateUser'] = user_token['username']
            note_entry_req['securityContext'] = security_context


            note_entry_helper = NoteEntryDBHelper(self.pers)
            note_entry_check = note_entry_helper.is_valid_note_entry(note_entry_req, goal='INS')

            if note_entry_check == "OK":
                self.logger.debug('Object passed validation for insert')
                note_entry = note_entry_helper.ins(security_context, note_entry_req)
            else:
                self.logger.debug('note_entrycheck Failed: %s', note_entry_check)
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'NoteEntry Integrity Check Failed',
                    note_entry_check
                )

            #http://www.restapitutorial.com/lessons/httpmethods.html
            resp.status = falcon.HTTP_201
            resp.body = dumps(note_entry)
        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_post failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )

    def on_put(self, req, resp, security_context):
        """
        Handles PUT requests - updates a note_entry
        """
        self.logger.debug('on_put running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']

            note_entry_req = self.web_util.parse_json_body(req.stream.read())
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'UPD_NOTE_ENTRY')

            note_entry_helper = NoteEntryDBHelper(self.pers)
            note_entry_req['updateUser'] = user_token['username']
            #Confirm object is valid for database update
            note_entry_check = note_entry_helper.is_valid_note_entry(note_entry_req, 'UPD')

            if note_entry_check == "OK":
                self.logger.debug('object passed validation for update')
                note_entry = note_entry_helper.upd(security_context, note_entry_req)
                resp.body = dumps(note_entry)
            else:
                self.logger.debug(
                    'Update Failed, throwing 400: %s',
                    note_entry_check
                    )
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'NoteEntry Integrity Check Failed',
                    note_entry_check
                    )
            if not note_entry:
                self.logger.debug('Update Failed, throwing 406')
                raise falcon.HTTPError(
                    falcon.HTTP_406,
                    'Something went wrong at the server.',
                    'Someone is already queued to research the issue.'
                    )

        except falcon.HTTPError:
            raise
        except:
            self.logger.error(
                "on_put failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )

    def on_delete(self, req, resp, security_context, note_entry_id):
        """
        Handles on Delete - Deletes a note_entry
        """
        self.logger.debug('on_del running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            self.web_util.check_csrf(user_token['ses'], req.headers)
            self.web_util.check_grant(security_context, user_token, 'DEL_NOTE_ENTRY')

            #on_delete can ignore the body,
            #likely to be dropped in web proxies anyway
            #valid_note_entry_test not required
            note_entry_helper = NoteEntryDBHelper(self.pers)
            note_entry_helper.drp(security_context, note_entry_id)
            resp.status = falcon.HTTP_200 #S=200 response signals success
            resp.body = "1"

        except falcon.HTTPError:
            raise
        except Exception:
            self.logger.error(
                "on_delete failed: %s",
                traceback.print_exc()
            )
            raise falcon.HTTPError(
                falcon.HTTP_400, #BAD Request
                'Something went wrong at the server.',
                'Someone is already queued to research the issue.'
            )
