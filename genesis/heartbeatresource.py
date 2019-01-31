"""
NoteEntry Web service
"""
#Standard Libraries
import logging
import traceback

#Third Party Libraries
import falcon
from bson.json_util import dumps





class HeartBeatResource(object):
    """
    Falcon web request handlers for note_entrys
    """

    def __init__(self,):
        """
        Initialization function
        """
        pass



    def on_get(self, req, resp,):
        """
        Handles GET requests - returns a note_entry object from DB
        """
        #self.logger.debug('on_get running')
        resp.status = falcon.HTTP_200
        resp.body = dumps({'status':'ok'})
