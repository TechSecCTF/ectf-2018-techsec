""" Bank Server
This module implements a bank server interface

The module exposes the following functions through a socket listening on
host 127.0.0.1 and port 1337

------------------------------------------------------------------------
function:
    withdraw

args:
    param1 (string - max length 1024): card_id of account to withdraw from
    param2 (string - max length ): amount to withdraw

returns:
    string: 'OKAY' on Success, 'ERROR' otherwise.
------------------------------------------------------------------------
function:
    check_balance

args:
    param1 (string - max length 1024): card_id of account to check balance

returns:
    String: Account balance on Success, empty string otherwise.
------------------------------------------------------------------------
"""

import uuid
from SimpleXMLRPCServer import SimpleXMLRPCServer
from bank_server import DB
import binascii
import hashlib
import struct
import hmac
import os
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util import Counter


class Bank(object):
    """
    request is OPCODE followed by fields separated by spaces, terminated with a
    newline

    response is either OKAY or ERROR followed by newline. OKAY may have one or
    more fields separated by spaces. ERROR may have any amount of text between
    the space and the newline.

    "withdraw <acct> <amount>\n"
    "OKAY\n"
    "balance <acct>\n"
    "OKAY <amount>\n"
    "ERROR\n"
    """

    def __init__(self, config, db_mutex, ready_event):
        super(Bank, self).__init__()
        self.bank_host = config['bank']['host']
        self.bank_port = int(config['bank']['port'])
        self.db_init = config['database']['db_init']
        self.db_path = config['database']['db_path']
        self.db_mutex = db_mutex
        self.db_obj = DB(
            db_mutex=self.db_mutex, db_init=self.db_init, db_path=self.db_path)
        self.server = SimpleXMLRPCServer((self.bank_host, self.bank_port))
        self.server.register_function(self.withdraw)
        self.server.register_function(self.check_balance)
        self.server.register_function(self.set_initial_pin)
        self.server.register_function(self.generate_session_nonce)
        self.server.register_function(self.change_pin)

        # Bank is initialized. Tell AdminBackend to report that ready_for_atm
        # is True.
        ready_event.set()
        self.server.serve_forever()


    def check_funds(self, card_id, atm_id, amount, hex_hsm_nonce):
        num_bills = self.db_obj.get_atm_num_bills(atm_id)
        if num_bills is None:
            return 'ERROR could not lookup atm \'' + str(atm_id) + '\''

        if num_bills < amount:
            return 'ERROR insufficient funds in atm \'' + str(atm_id) + '\''

        balance = self.db_obj.get_balance(card_id)
        if balance is None:
            return 'ERROR could not lookup card \'' + str(card_id) + '\''

        final_amount = balance - amount
        if final_amount >= 0:
            self.db_obj.set_balance(card_id, final_amount)
            self.db_obj.set_atm_num_bills(atm_id, num_bills - amount)

            atm_aes_key = binascii.unhexlify(self.db_obj.get_atm_aes_key(atm_id))

            # Compute HMAC for HSM
            raw_hsm_nonce = hex_hsm_nonce.decode('hex')
            hex_hmac = hmac.new(atm_aes_key, atm_id + raw_hsm_nonce, hashlib.sha256).hexdigest()

            return 'OKAY ' + hex_hmac
        else:
            return 'ERROR insufficient funds'


    def withdraw(self, card_id, hex_card_hmac, entered_pin, atm_id, hex_hsm_nonce, amount):
        try:
            amount = int(amount)
        except ValueError:
            return 'ERROR withdraw command usage: withdraw <atm_id> <card_id> <amount>'

        if not self.verify_hmac(card_id, hex_card_hmac):
            return 'ERROR check_balance: could not verify HMAC'

        #Final check, pin
        if not self.check_pin(card_id, entered_pin):
            return 'ERROR check_balance: pin incorrect'

        return self.check_funds(card_id, atm_id, amount, hex_hsm_nonce)


    def generate_session_nonce(self, card_id):
        hex_old_session_nonce = self.db_obj.get_card_nonce(card_id)
        if hex_old_session_nonce is None:
            return 'ERROR could not lookup card \'' + str(card_id) + '\''
        return 'OKAY ' + hex_old_session_nonce


    def encrypt_balance(self, card_id, atm_id, hex_hsm_nonce):
        raw_hsm_nonce = binascii.unhexlify(hex_hsm_nonce)
        balance = str(self.db_obj.get_balance(card_id))
        if balance is None:
            return 'ERROR could not lookup card \'' + str(card_id) + '\''

        # Encrypt balance and return it
        # First, pad it out with A's
        assert len(balance) <= 16
        balance = balance.ljust(16, 'A')

        atm_aes_key = binascii.unhexlify(self.db_obj.get_atm_aes_key(atm_id))

        raw_atm_rand_iv = os.urandom(16)
        hex_atm_rand_iv = binascii.hexlify(raw_atm_rand_iv)
        ctr_func = Counter.new(128, initial_value = int(hex_atm_rand_iv, 16))
        enc_cipher = AES.new(atm_aes_key, AES.MODE_CTR, counter = ctr_func)
        raw_encrypted_balance = enc_cipher.encrypt(balance)

        hex_hmac = hmac.new(atm_aes_key, raw_encrypted_balance + raw_atm_rand_iv + raw_hsm_nonce, hashlib.sha256).hexdigest()

        return 'OKAY ' + hex_hmac + hex_atm_rand_iv + raw_encrypted_balance.encode("hex")


    def verify_hmac(self, card_id, hex_card_hmac):
        raw_card_hmac = binascii.unhexlify(hex_card_hmac)
        raw_card_aes_key = binascii.unhexlify(self.db_obj.get_card_aes_key(card_id))

        raw_true_nonce = self.db_obj.get_card_nonce(card_id).decode("hex")
        if not raw_true_nonce or not raw_card_aes_key:
            return False

        # Set a new nonce
        hex_session_nonce = binascii.hexlify(os.urandom(4))
        self.db_obj.set_card_nonce(card_id, hex_session_nonce)

        # Check HMACs
        raw_true_hmac = hmac.new(raw_card_aes_key, card_id + raw_true_nonce, hashlib.sha256).digest()

        if not hmac.compare_digest(raw_card_hmac, raw_true_hmac):
            return False

        return True


    def check_pin(self, card_id, entered_pin):
        card_pin_hash = self.db_obj.get_card_pin_hash(card_id).encode('utf-8')

        if not bcrypt.checkpw(entered_pin, card_pin_hash):
            return False

        return True


    def check_balance(self, card_id, hex_card_hmac, entered_pin, atm_id, hex_hsm_nonce):

        if not self.verify_hmac(card_id, hex_card_hmac):
            return 'ERROR check_balance: could not verify HMAC'

        #Final check, pin
        if not self.check_pin(card_id, entered_pin):
            return 'ERROR check_balance: pin incorrect'

        return self.encrypt_balance(card_id, atm_id, hex_hsm_nonce)

    def set_initial_pin(self, card_id, pin):

        try:
            uuid.UUID(str('{' + card_id + '}'))
        except ValueError:
            return 'ERROR card_id not valid'

        salt = bcrypt.gensalt(13)
        pin_hash = bcrypt.hashpw(pin, salt)
        self.db_obj.update_pin(card_id, pin_hash)

        return 'OKAY ' + card_id

    def change_pin(self, card_id, hex_card_hmac, old_pin, new_pin):
        if not self.verify_hmac(card_id, hex_card_hmac):
            return 'ERROR check_balance: could not verify HMAC'

        #Check old pin
        if not self.check_pin(card_id, old_pin):
            return 'ERROR check_balance: pin incorrect'

        # Set new pin
        salt = bcrypt.gensalt(13)
        pin_hash = bcrypt.hashpw(new_pin, salt)
        self.db_obj.update_pin(card_id, pin_hash)
        return 'OKAY ' + card_id