from psoc import Psoc
import struct
from serial_emulator import HSMEmulator
import logging
import time
import binascii


class HSM(Psoc):
    """Interface for communicating with the HSM

    Args:
        port (str, optional): Serial port connected to HSM
        verbose (bool, optional): Whether to print debug messages

    Note:
        Calls to get_uuid and withdraw must be alternated to remain in sync
        with the HSM
    """

    def __init__(self, port=None, verbose=False, dummy=False):
        self.port = port
        self.verbose = verbose
        self.dummy = dummy

    def initialize(self):
        super(HSM, self).__init__('HSM', self.port, self.verbose)
        self.DECRYPT = 1
        self.DISPENSE_BILLS = 2
        self.GET_UUID = 3
        self._vp('Please connect HSM to continue.')
        while not self.connected and not self.dummy:
            time.sleep(2)
        self._vp('Initialized')

    def get_uuid(self):
        """Retrieves the UUID from the HSM, returns a session nonce as well

        Returns:
            str: UUID of HSM
            str: session nonce
        """
        self._sync(False)

        self._vp('Sending GET_UUID command to HSM')
        self._send_op(self.GET_UUID)

        uuid = self._pull_msg()
        nonce = self._pull_msg()

        if uuid == 'P':
            self._vp('Security module not yet provisioned!', logging.error)
            return None

        self._vp('Got UUID %s' % uuid)
        self._vp('Got session nonce %s' % repr(nonce))

        return uuid, nonce


    def _send_op(self, op):
        self._push_msg(str(op))

        while self._pull_msg() != 'K':
            self._vp('HSM hasn\'t received op', logging.error)
        self._vp('HSM received op')

    def decrypt(self, raw_hmac, raw_iv, raw_enc_msg):
        # Sync and get UUID
        # self.get_uuid()
        self._sync(False)

        self._vp('Sending DECRYPT command to HSM')
        self._send_op(self.DECRYPT)

        self._vp("Sending message to decrypt")
        self._push_msg("%s\00" % raw_hmac)
        self._push_msg("%s\00" % raw_iv)
        self._push_msg("%s\00" % raw_enc_msg)

        msg = self._pull_msg()
        self._vp("HSM returned %s" % repr(msg))

        if msg == 'BAD':
            return 'HSM could not decrypt message'

        return msg

    def withdraw(self, raw_atm_hmac, amount):
        """Attempts to withdraw bills from the HSM

        Args:
            raw_atm_hmac (str): Challenge hmac of HSM
            amount (int): Number of bills to withdraw from HSM

        Returns:
            list of str: List of dispensed bills on success
            str: 'Insufficient funds' if the UUID was incorrect
                 'Not enough bills in ATM' if HSM doesn't have enough bills
                    to complete request
        """

        self._sync(False)

        self._vp('Sending DISPENSE_BILLS command to HSM')
        self._send_op(self.DISPENSE_BILLS)

        self._push_msg(raw_atm_hmac)
        msg = struct.pack('B', amount)
        self._push_msg(msg)

        msg = self._pull_msg()
        self._vp('HSM replied %s' % repr(msg))
        if msg == 'BAD':
            return 'Not enough bills in ATM'

        bills = []
        for i in range(amount):
            bill = self._pull_msg()
            self._vp('Received bill %d/%d: \'%s\'' % (i + 1, amount, bill))

            bills.append(bill)

        return bills

    def provision(self, blob, bills):
        """Attempts to provision HSM

        Args:
            blob (str): blob for HSM
            bills (list of str): List of bills to store in HSM

        Returns:
            bool: True if HSM provisioned, False otherwise
        """
        self._sync(True)

        msg = self._pull_msg()
        if msg != 'P':
            self._vp('HSM already provisioned!', logging.error)
            return False
        self._vp('HSM sent provisioning message')

        self._push_msg('%s\00' % blob)
        msg = self._pull_msg()

        while msg != 'K':
            self._vp('HSM hasn\'t accepted blob \'%s\'' % blob, logging.error)
            msg = self._pull_msg()
        self._vp('HSM accepted blob \'%s\'' % blob)

        self._push_msg(struct.pack('B', len(bills)))
        while self._pull_msg() != 'K':
            self._vp('HSM hasn\'t accepted number of bills', logging.error)
        self._vp('HSM accepted number of bills')

        for bill in bills:
            msg = bill.strip()
            self._vp('Sending bill \'%s\'' % msg.encode('hex'))
            self._push_msg(msg)

            while self._pull_msg() != 'K':
                self._vp('HSM hasn\'t accepted bill', logging.error)
            self._vp('HSM accepted bill')

        self._vp('All bills sent! Provisioning complete!')

        return True


class DummyHSM(HSM):
    """Emulated HSM for testing

    Arguments:
        verbose (bool, optional): Whether to print debug messages
        provision (bool, optional): Whether to start the HSM ready
            for provisioning
    """
    def __init__(self, verbose=False, provision=False):
        ser = HSMEmulator(verbose=verbose, provision=provision)
        super(DummyHSM, self).__init__(port=ser, verbose=verbose, dummy=True)
