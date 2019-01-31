"""
FileUpload Web service
"""
#Standard Libraries
import logging
import traceback
import uuid
import os

#Third Party Libraries
import falcon
from bson.json_util import dumps
from google.cloud import storage
from google.cloud.storage import Blob

#App specific libraries
from genesis.filestoredbhelper import FileStoreDBHelper


class FileUploadResource(object):
    """
    Falcon web request handlers for file_uploads
    Relevant Pictures: "FS_ADD", "FS_GET", "FS_UPD", "FS_DEL"
    """

    def __init__(self, persistence, cfg, web_util):
        self.logger = logging.getLogger('app')
        self.logger.debug("instantiated")
        self.pers = persistence
        self.web_util = web_util
        self.cfg = cfg

    def on_get(self, req, resp, security_context='', file_store_id=''):
        """
        Handles GET requests - returns a file_store object from DB
        """
        self.logger.debug('on_get running')
        try:
            #Gather inputs
            user_token = req.context['user']['user']
            #self.logger.debug("token" + json.dumps(req.context['user']))

            #Check to see if file_store is permitted to select in this context

            self.web_util.check_grant(security_context, user_token, 'FS_GET')


            #Initialize Database components

            file_store_helper = FileStoreDBHelper(self.pers)
            if file_store_id != '':
                self.logger.debug('searching for %s', file_store_id)
                file_store = file_store_helper.sel(security_context, file_store_id)
                self.logger.debug('found %s', dumps(file_store))
            fs_filename = file_store_id + self.get_extension_from_filename(file_store['fileName'])
            fs_fullpath = self.cfg.FILE_STORE_PATH + fs_filename



            storage_client = storage.Client(project=self.cfg.GCP_PROJECT_NAME)
            bucket = storage_client.get_bucket(self.cfg.GCP_CS_BUCKET_NAME)
            blob = Blob(file_store['cloudId'], bucket, encryption_key=self.cfg.GCP_CS_ENCRTYPION_KEY)
            local_file_name = '/tmp/' +  file_store['cloudId'].replace("/","_")
            with open(local_file_name, "wb") as file_obj:
                blob.download_to_file(file_obj)

            
            resp.content_type = file_store['contentType']
            resp.stream = open(local_file_name,'rb')
            resp.stream_len = file_store['fileSize']


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
        Handles POST requests - uploads a file
        """
        self.logger.debug('on_post running')
        try:
            #Gather Inputs
            user_token = req.context['user']['user']
            #file_upload_req = self.web_util.parse_json_body(req.stream.read())
            #self.logger.debug('Posted Data: ' + dumps(file_upload_req))

            #Gaurd against CSRF
            #TODO Fix CSRF
            #self.web_util.check_csrf(user_token['ses'], req.headers)

            #TODO Add this security Check Back in
            #self.web_util.check_grant(security_context, user_token, 'FS_ADD')
            file_candidate = req.get_param('uploadCandidate')


            #TODO whitelist extenstions, probably via config.

            # Read image as binary
            raw_file_from_web = file_candidate.file.read()
            file_uuid4 = str(uuid.uuid4())


            extension = self.get_extension_from_filename(file_candidate.filename)

            system_file_name = self.cfg.FILE_STORE_PATH + file_uuid4
            system_file = open(system_file_name, "wb")
            system_file.write(raw_file_from_web)
            system_file.close()

            destination_blob_name = file_uuid4 + '/' + file_candidate.filename
            #
            #

            storage_client = storage.Client(project=self.cfg.GCP_PROJECT_NAME)
            bucket = storage_client.get_bucket(self.cfg.GCP_CS_BUCKET_NAME)
            blob = Blob(destination_blob_name, bucket, encryption_key=self.cfg.GCP_CS_ENCRTYPION_KEY)
            blob.upload_from_filename(system_file_name, predefined_acl='private')

            file_store_helper = FileStoreDBHelper(self.pers)
            file_store_req = {
                '_id': 0,
                'fileName': file_candidate.filename,
                'fileSize': len(raw_file_from_web),
                'logicalPath': "/",
                'contentType': file_candidate.type,
                'cloudId': destination_blob_name,
                'securityContext': security_context,
                'createUser': user_token['username'],
                'updateUser': user_token['username'],
            }
            file_store_check = file_store_helper.is_valid_file_store(file_store_req, goal='INS')

            if file_store_check == "OK":
                self.logger.debug('Object passed validation for insert')
                file_store = file_store_helper.ins(security_context, file_store_req)
            else:
                self.logger.debug('file_storecheck Failed: %s', file_store_check)
                raise falcon.HTTPError(
                    falcon.HTTP_400,
                    'FileStore Integrity Check Failed',
                    file_store_check
                )

            if os.path.exists(system_file_name):
                os.remove(system_file_name)


            del raw_file_from_web
            del system_file
            del file_candidate

            self.logger.debug('on_post done')
            resp.status = falcon.HTTP_201
            resp.body = dumps(file_store)

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

    def get_extension_from_filename(self, filename):
        """
        standardized file method extraction
        Note: may need additional logic
        """
        return filename[-4:]
