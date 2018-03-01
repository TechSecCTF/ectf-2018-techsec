"""Backend of ATM interface for xmlrpc"""

import logging
import sys
import socket
import xmlrpclib
import binascii

HMAC_LEN = 64
IV_LEN = 32


class Bank:
    """Interface for communicating with the bank

    Args:
        address (str): IP address of bank
        port (int): Port to connect to
    """

    def __init__(self, address='127.0.0.1', port=1337):
        try:
            self.bank_rpc = xmlrpclib.ServerProxy('http://' + address + ':' + str(port))
        except socket.error:
            logging.error('Error connecting to bank server')
            sys.exit(1)
        logging.info('Connected to Bank at %s:%s' % (address, str(port)))

    def check_balance(self, card_id, raw_card_hmac, pin, hsm_id, raw_hsm_nonce):
        """Requests the balance of the account associated with the card_id

        Args:
            card_id (str): UUID of the ATM card to look up
            card_hmac: raw hex card hmac of above two things
            pin:
            hsm_id:
            raw_hsm_nonce: challenge nonce from HSM to bank

        Returns:
            hmac
            iv of encrypted balance
            encrypted balance
            bool: False on failure
        """
        logging.info('check_balance: Sending request to Bank')
        # logging.info(type(pin))
        res = self.bank_rpc.check_balance(card_id, binascii.hexlify(raw_card_hmac), pin, hsm_id, binascii.hexlify(raw_hsm_nonce))
        if res[:4] == 'OKAY':
            # return HMAC, IV, and enc_msg
            return (res[5:5+HMAC_LEN].decode('hex'), res[5 + HMAC_LEN:5 + HMAC_LEN + IV_LEN].decode('hex'), res[5 + HMAC_LEN + IV_LEN:].decode('hex'))
        logging.info('check_balance: Bank request failed %s', res)
        return False    

    def withdraw(self, card_id, raw_card_hmac, pin, hsm_id, raw_hsm_nonce, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            card_id (str): UUID of the ATM card
            card_hmac
            hsm_id (str): UUID of the HSM
            raw_hsm_nonce (str): challenge nonce of HSM
            amount (str): Requested amount to withdraw

        Returns:
            str: hmac on success
            bool: False on failure
        """
        logging.info('withdraw: Sending request to Bank')
        res = self.bank_rpc.withdraw(card_id, raw_card_hmac.encode('hex'), pin, hsm_id, raw_hsm_nonce.encode('hex'), amount)
        if res[:4] == 'OKAY':
            return res[5:].decode('hex')
        logging.info('withdraw: Bank request failed %s', res)
        return False

    def get_session_nonce(self, card_id):
        """ Requests a new session nonce for a card communication

        return:
            str: Session nonce
        """
        res = self.bank_rpc.get_session_nonce(card_id)
        if res[:4] == 'OKAY':
            return res[5:].decode('hex')
        logging.info('get_session_nonce: Bank request failed %s', res)
        return False


    def set_initial_pin(self, card_id, pin):
        """Sends initial pin for new card to bank

        Returns:
            str: card_id on success
            bool: False on failure
        """

        logging.info('set_initial_pin: Sending request to Bank')
        res = self.bank_rpc.set_initial_pin(card_id, pin)
        if res[:4] == 'OKAY':
            return res[5:]
        logging.info('set_initial_pin: Bank request failed %s', res)
        return False

    def change_pin(self, card_id, raw_card_hmac, old_pin, new_pin):
        """
        Changes pin on card if old_pin and hmac are correct

        :param card_id:
        :param raw_card_hmac:
        :param old_pin:
        :param new_pin:
        :return:
        """
        res = self.bank_rpc.change_pin(card_id, raw_card_hmac.encode('hex'), old_pin, new_pin)
        if res[:4] == 'OKAY':
            return res[5:]
        logging.info('change_pin: Bank request failed %s', res)
        return False

class DummyBank:
    """Emulated bank for testing"""

    def __init__(self):
        pass

    def withdraw(self, hsm_id, card_id, amount):
        """Authorizes a requested withdrawal

        Args:
            hsm_id (str): UUID of HSM
            card_id (doesn't matter): Isn't used
            amount: (doesn't matter): Isn't used

        Returns:
            str: hsm_id
        """
        return hsm_id

    def check_balance(self, card_id):
        """Authorizes a requested balance check

        Args:
            card_id (doesn't matter): Isn't used

        Returns:
            int: Balance of 2018
        """
        return 2018

    def set_initial_pin(self, card_id, pin):
        return card_id


