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
import os
from Crypto.Cipher import AES


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

    def check_balance(self, card_id, aes_iv, card_hmac):
        aes_key = self.db_obj.get_card_aes_key(card_id)
        if aes_key:
            true_hmac = hmac.new(binascii.unhexlify(aes_key, enc_uuid + aes_iv, hashlib.sha256).hexdigest())

            if not hmac.compare_digest(card_hmac, true_hmac):
                return 'ERROR check_balance: invalid hmac on message'
        else:
            return 'ERROR could not lookup account \'' + str(card_id) + '\''

        # Now, try to decrypt card id
        # assert len(aes_iv)
        cipher = AES.new(aes_key, AES.MODE_CTR, counter = aes_iv)
        card_id = cipher.decrypt(enc_uuid)
        try:
            uuid.UUID(str('{' + card_id + '}'))
        except ValueError:
            return 'ERROR card_id not present or formatted correctly'

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

        salt = binascii.hexlify(os.urandom(8))
        pin_hash = hashlib.sha256(card_id + pin + salt).hexdigest()
        self.db_obj.update_pin(card_id, pin_hash, salt)

        return 'OKAY ' + card_id
