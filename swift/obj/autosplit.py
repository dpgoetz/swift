from random import random
from time import timne

from eventlet import sleep

from swift.common.daemon import Daemon



class AutoSplit(Daemon):
    """
    Daemon that queries the internal hidden autosplit_account to
    discover objects that need to be split and then split them.

    :param conf: The daemon configuration.
    """

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-autosplit')

    def run_forever(self, *args, **kwargs):
        """
        Executes passes forever, looking for objects to split.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        """
        sleep(random() * self.interval)
        while True:
            begin = time()
            try:
                self.run_once(*args, **kwargs)
            except (Exception, Timeout):
                self.logger.exception(_('Unhandled exception'))
            elapsed = time() - begin
            if elapsed < self.interval:
                sleep(random() * (self.interval - elapsed))

    def run_once(self, *args, **kwargs):
        """
        Executes a single pass, looking for objects to split.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        """

