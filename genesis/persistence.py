""" 
Wrapper class to house connections to any persistence mechanisms used
"""

class Persistence(object):
    """ 
    Class holds these public variables to pass around the
    application.  Expectation is it could grow for a 
    polyglot implementation
    """
    nosql_db = None
    sql_db_engine = None
    sql_meta = None
