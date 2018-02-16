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

    def __init__(self, config, db_mutex):
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
        self.server.serve_forever()

    def withdraw(self, atm_id, card_id, amount):
        try:
            amount = int(amount)
        except ValueError:
            return 'ERROR withdraw command usage: withdraw <atm_id> <card_id> <amount>'

        atm = self.db_obj.get_atm(atm_id)
        if atm is None:
            return 'ERROR could not lookup atm \'' + str(atm_id) + '\''

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
            return 'OKAY ' + atm_id
        else:
            return 'ERROR insufficient funds'

    # TODO: Encrypt all return msgs 
    def check_balance(self, card_id, enc_msg, aes_iv, card_hmac, entered_pin, atm_id):
        enc_msg = binascii.unhexlify(enc_msg)
        aes_iv = binascii.unhexlify(aes_iv)
        card_hmac = binascii.unhexlify(card_hmac)

        card_aes_key = binascii.unhexlify(self.db_obj.get_card_aes_key(card_id))

        true_nonce = self.db_obj.get_card_nonce(card_id)
        if not true_nonce or not card_aes_key:
            return 'ERROR could not lookup account \'' + str(card_id) + '\''
        # TODO: implement reliable messaging system 
        new_nonce = true_nonce + 1 
        self.db_obj.set_card_nonce(card_id, new_nonce)

        # Now, decrypt and check nonce
        ctr_func =  Counter.new(128, initial_value=int(binascii.hexlify(aes_iv), 16))
        cipher = AES.new(card_aes_key, AES.MODE_CTR, counter = ctr_func)
        card_nonce = cipher.decrypt(enc_msg)

        assert len(card_nonce) == 4
        card_nonce = struct.unpack(">I", card_nonce)[0]
        print "card_nonce", card_nonce
        print "true_nonce", true_nonce

        if card_nonce != true_nonce:
            return 'ERROR replay nonce is incorrect'

        # Check HMACs 
        true_hmac = hmac.new(card_aes_key, enc_msg + aes_iv, hashlib.sha256).digest()

        if not hmac.compare_digest(card_hmac, true_hmac):
            return 'ERROR check_balance: invalid hmac on message'

        #Final check, pin
        card_pin_hash = self.db_obj.get_card_pin_hash(card_id).encode('utf-8')
        print("card pin hash", card_pin_hash)

        if not bcrypt.checkpw(entered_pin, card_pin_hash):
            return 'ERROR pin incorrect'

        balance = str(self.db_obj.get_balance(card_id))
        if balance is None:
            return 'ERROR could not lookup account \'' + str(card_id) + '\''
        else:
            # Encrypt balance and return it 
            # First, pad it out with A's
            # TODO: Break out into new comm 

            assert len(balance) <= 16
            balance = balance.ljust(16, 'A')
            print("balance", balance)

            atm_aes_key = binascii.unhexlify(self.db_obj.get_atm_aes_key(atm_id))
            print "atm_aes_key", repr(atm_aes_key)

            atm_rand_iv = os.urandom(16)
            ctr_func = Counter.new(128, initial_value=int(binascii.hexlify(atm_rand_iv), 16))
            enc_cipher = AES.new(atm_aes_key, AES.MODE_CTR, counter = ctr_func)
            encrypted_balance = enc_cipher.encrypt(balance)

            true_hmac = hmac.new(atm_aes_key, encrypted_balance + atm_rand_iv, hashlib.sha256).hexdigest()

            return 'OKAY ' + true_hmac + atm_rand_iv.encode("hex") + encrypted_balance.encode("hex")

    def set_initial_pin(self, card_id, pin):

        try:
            uuid.UUID(str('{' + card_id + '}'))
        except ValueError:
            return 'ERROR card_id not valid'

        salt = bcrypt.gensalt(13)
        pin_hash = bcrypt.hashpw(pin, salt)
        self.db_obj.update_pin(card_id, pin_hash)

        return 'OKAY ' + card_id
