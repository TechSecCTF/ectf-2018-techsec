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
    def check_balance(self, card_id, enc_msg, aes_iv, card_hmac, entered_pin):
        enc_msg = binascii.unhexlify(enc_msg)
        aes_iv = binascii.unhexlify(aes_iv)
        card_hmac = binascii.unhexlify(card_hmac)

        aes_key = binascii.unhexlify(self.db_obj.get_card_aes_key(card_id))

        true_nonce = self.db_obj.get_card_nonce(card_id)
        if not true_nonce or not aes_key:
            return 'ERROR could not lookup account \'' + str(card_id) + '\''
        # TODO: implement reliable messaging system 
        new_nonce = true_nonce + 1 
        self.db_obj.set_card_nonce(card_id, new_nonce)

        # Now, decrypt and check nonce
        ctr_func =  Counter.new(128, initial_value=int(binascii.hexlify(aes_iv), 16))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter = ctr_func)
        card_nonce = cipher.decrypt(enc_msg)

        assert len(card_nonce) == 4
        card_nonce = struct.unpack(">I", card_nonce)[0]
        print "card_nonce", card_nonce
        print "true_nonce", true_nonce

        if card_nonce != true_nonce:
            return 'ERROR replay nonce is incorrect'

        # Check HMACs 
        true_hmac = hmac.new(aes_key, enc_msg + aes_iv, hashlib.sha256).digest()

        if not hmac.compare_digest(card_hmac, true_hmac):
            return 'ERROR check_balance: invalid hmac on message'

        #Final check, pin

        card_pin_hash = self.db_obj.get_card_pin_hash(card_id).encode('utf-8')

        if not bcrypt.checkpw(entered_pin, card_pin_hash):
            return 'ERROR pin incorrect'

        balance = self.db_obj.get_balance(card_id)
        if balance is None:
            return 'ERROR could not lookup account \'' + str(card_id) + '\''
        else:
            return 'OKAY ' + str(balance)

    def set_initial_pin(self, card_id, pin):

        try:
            uuid.UUID(str('{' + card_id + '}'))
        except ValueError:
            return 'ERROR card_id not valid'

        salt = bcrypt.gensalt(13)
        pin_hash = bcrypt.hashpw(pin, salt)
        self.db_obj.update_pin(card_id, pin_hash)

        return 'OKAY ' + card_id
