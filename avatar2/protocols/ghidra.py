
import logging


from ghidra_bridge import GhidraBridge



class GhidraBridgeProtocol(object):
    """

        Please install ghidra_bridge as explained in the webpage: https://github.com/justfoxing/ghidra_bridge
    """

    def __init__(self, avatar=None, origin=None):
        """
        """

        self._queue = queue.Queue() if avatar is None \
                else avatar.queue
        self._fast_queue = queue.Queue() if avatar is None \
                else avatar.fast_queue


        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

        self.gbridge = GhidraBridge(namespace=globals())
        self.log.debug("Ghidra bridge connected")


    def shutdown(self):
        self.gbridge.remote_shutdown()

        # Implement Target methods

