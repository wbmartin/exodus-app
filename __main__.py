"""
Example Application
Usage:
    falcon-example [options]
Options:
    -h --help                   Show this screen.
"""

#from docopt import docopt
from gunicorn.app.base import BaseApplication
from gunicorn.workers.sync import SyncWorker

from genesis.app import GenesisService
from  genesis.config import Config
import logging
from genesis.customlogging import  setup_logging

class CustomWorker(SyncWorker):
    """ TODO DETERMINE WHAT THIS DOES"""
    def handle_quit(self, sig, frame):
        self.app.application.stop(sig)
        super(CustomWorker, self).handle_quit(sig, frame)

    def run(self):
        self.app.application.start()
        super(CustomWorker, self).run()


class GunicornApp(BaseApplication):
    """ Custom Gunicorn application
    This allows for us to load gunicorn settings from an external source
    """
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super(GunicornApp, self).__init__()

    def load_config(self):
        for key, value in self.options.items():
            self.cfg.set(key.lower(), value)

        self.cfg.set('worker_class', '__main__.CustomWorker')

    def load(self):
        return self.application


def main():
    """ Main Function"""
    cfg = Config()

    #logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    #TODO Start writing line numbers into log
    setup_logging(config_path=cfg.LOGGING_CONFIG_FILE)

    api_app = GenesisService(cfg)
    gunicorn_app = GunicornApp(api_app, cfg.GUNICORN)

    gunicorn_app.run()

if __name__ == '__main__':
    main()
