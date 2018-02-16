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

    def check_balance(self, card_id, enc_msg, aes_iv, card_hmac, pin, hsm_id):
        """Requests the balance of the account associated with the card_id

        Args:
            card_id (str): UUID of the ATM card to look up

        Returns:
            iv of encrypted balance
            encrypted balance
            bool: False on failure
        """
        logging.info('check_balance: Sending request to Bank')
        # logging.info(type(pin))
        res = self.bank_rpc.check_balance(card_id, binascii.hexlify(enc_msg), binascii.hexlify(aes_iv), binascii.hexlify(card_hmac), pin, hsm_id)
        if res[:4] == 'OKAY':
            # return HMAC, IV, and enc_msg
            return res[5:5+HMAC_LEN], res[5 + HMAC_LEN:5 + HMAC_LEN + IV_LEN], res[5 + HMAC_LEN + IV_LEN:]
        logging.info('check_balance: Bank request failed %s', res)
        return False    

    def withdraw(self, hsm_id, card_id, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            hsm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            amount (str): Requested amount to withdraw

        Returns:
            str: hsm_id on success
            bool: False on failure
        """
        logging.info('withdraw: Sending request to Bank')
        res = self.bank_rpc.withdraw(hsm_id, card_id, amount)
        if res[:4] == 'OKAY':
            return res[5:]
        logging.info('withdraw: Bank request failed %s', res)
        return False

    def set_initial_pin(self, card_id, pin):
        """Sends initial pin for new card to bank

        Returns:
            str: card_id on success
            bool: False on failure
        """

        logging.info('set_initial_pin: Sending request to Bank')
        logging.info("card blob %s" % card_id)
        res = self.bank_rpc.set_initial_pin(card_id, pin)
        if res[:4] == 'OKAY':
            return res[5:]
        logging.info('set_initial_pin: Bank request failed %s', res)
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


