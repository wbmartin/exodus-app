"""Custom Logging Setup/config"""
import os
import json
import logging.config

def setup_logging(
        config_path='/tmp/logging.json',
        default_level=logging.INFO,
        env_key='LOG_CFG'
):
    """
    Setup logging configuration
    """
    path = config_path
    value = os.getenv(env_key, None)
    logging.getLogger().error("trying to config Logger %s", os.getcwd())
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as log_config_file:
            config = json.load(log_config_file)
        logging.config.dictConfig(config)
    else:
        logging.getLogger().error("file note found: %s", os.getcwd())
        raise Exception("Failed to open log configuration file: " + path)
