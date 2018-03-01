from psoc import Psoc
from serial_emulator import CardEmulator
import logging
import hmac

class Card(Psoc):
    """Interface for communicating with the ATM card

    Args:
        port (str, optional): Serial port connected to an ATM card
            Default is dynamic card acquisition
        verbose (bool, optional): Whether to print debug messages
    """
    def __init__(self, port=None, verbose=False):
        self.port = port
        self.verbose = verbose

    def initialize(self):
        super(Card, self).__init__('CARD', self.port, self.verbose)
        self.COMPUTE_HMAC = 2
        self.GET_UUID = 3

    def _send_challenge_nonce(self, nonce):
        """Requests authentication from the ATM card

        Args:
            nonce (str): Challenge nonce

        Returns:
            bool: True if ATM card verified authentication, False otherwise
        """
        self._push_msg(nonce)

        resp = self._pull_msg()
        return resp == 'OK'

    def _get_uuid(self):
        """Retrieves the UUID from the ATM card

        Returns:
            uuid: UUID of ATM card
        """

        self._sync(False)

        self._send_op(self.GET_UUID)

        uuid = self._pull_msg()

        return uuid

    def _send_op(self, op):
        """Sends requested operation to ATM card

        Args:
            op (int): Operation to send from [self.COMPUTE_HMAC, self.GET_UUID]
        """
        self._vp('Sending op %d' % op)
        self._push_msg(str(op))

        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t received op', logging.error)
        self._vp('Card received op')

    def compute_hmac(self, raw_bank_nonce):
        """Requests for a balance to be checked

        Args:
            pin (str): Challenge PIN

        Returns:
            str: UUID of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)

        # Send balance op
        self._send_op(self.COMPUTE_HMAC)

        # Send challenge nonce to card
        if not self._send_challenge_nonce(raw_bank_nonce):
            return False

        # Get hmac
        msg = self._pull_msg()
        return msg

    def provision(self, blob):
        """Attempts to provision a new ATM card

        Args:
            blob (str): New blob for ATM card

        Returns:
            bool: True if provisioning succeeded, False otherwise
        """
        self._sync(True)

        msg = self._pull_msg()
        if msg != 'P':
            self._vp('Card already provisioned!', logging.error)
            return False
        self._vp('Card sent provisioning message')

        self._push_msg('%s\00' % blob)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted provisioning blob', logging.error)
        self._vp('Card accepted provisioning blob')

        self._vp('Provisioning complete')

        return True


class DummyCard(Card):
    """Emulated ATM card for testing

    Arguments:
        verbose (bool, optional): Whether to print debug messages
        provision (bool, optional): Whether to start the ATM card ready
            for provisioning
    """
    def __init__(self, verbose=False, provision=False):
        ser = CardEmulator(verbose=verbose, provision=provision)
        super(DummyCard, self).__init__(ser, verbose)
