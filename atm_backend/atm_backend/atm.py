import logging
import binascii
from interface.psoc import DeviceRemoved, NotProvisioned


class ATM(object):
    """Interface for ATM xmlrpc server

    Args:
        bank (Bank or BankEmulator): Interface to bank
        hsm (HSM or HSMEmulator): Interface to HSM
        card (Card or CardEmulator): Interface to ATM card
    """

    def __init__(self, bank, hsm, card):
        self.bank = bank
        self.hsm = hsm
        self.card = card

    def hello(self):
        logging.info("Got hello request")
        return "hello"

    def check_balance(self, pin):
        """Tries to check the balance of the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN associated with the connected ATM card

        Returns:
            str: Balance on success
            bool: False on failure
        """
        hsm_id, raw_hsm_session_nonce = self.hsm.get_uuid()

        if not self.card.inserted():
            logging.info('No card inserted')
            return False

        try:
            logging.info('check_balance: Requesting card_id')
            card_id = self.card._get_uuid()

            logging.info('check_balance: Requesting session nonce from bank')
            raw_card_session_nonce = self.bank.get_session_nonce(card_id)
            if not raw_card_session_nonce:
                return False

            logging.info('check_balance: Computing HMAC on card')
            raw_card_hmac = self.card.compute_hmac(raw_card_session_nonce)

            # get balance from bank
            if card_id and raw_card_hmac:
                logging.info('check balance: Requesting hsm_id from hsm')
                hsm_id, raw_hsm_session_nonce = self.hsm.get_uuid()

                # request withdrawal from bank if HSM gives UUID
                if hsm_id:
                    logging.info('check_balance: Requesting balance from Bank')
                    check_balance_vals = self.bank.check_balance(card_id, raw_card_hmac, pin, hsm_id, raw_hsm_session_nonce)


                    if check_balance_vals:
                        raw_atm_hmac, raw_atm_iv, raw_enc_balance = check_balance_vals

                        # send to HSM for decryption
                        logging.info("Sending balance to HSM for decryption")
                        res = self.hsm.decrypt(raw_atm_hmac, raw_atm_iv, raw_enc_balance)
                        res = res.strip('A')
                        try:
                            return int(res)
                        except ValueError:
                            return False
            logging.info('check_balance failed')
            return False
        except DeviceRemoved:
            logging.info('ATM card was removed!')
            return False
        except NotProvisioned:
            logging.info('ATM card has not been provisioned!')
            return False

    def change_pin(self, old_pin, new_pin):
        """Tries to change the PIN of the connected ATM card

        Args:
            old_pin (str): 8 digit PIN currently associated with the connected
                ATM card
            new_pin (str): 8 digit PIN to associate with the connected ATM card

        Returns:
            bool: True on successful PIN change
            bool: False on failure
        """
        if not self.card.inserted():
            logging.info('No card inserted')
            return False
        try:
            logging.info('change_pin: Requesting card_id')
            card_id = self.card._get_uuid()

            logging.info('change_pin: Requesting session nonce from bank')
            raw_card_session_nonce = self.bank.get_session_nonce(card_id)

            logging.info('change_pin: Computing HMAC on card')
            raw_card_hmac = self.card.compute_hmac(raw_card_session_nonce)

            if not self.bank.change_pin(card_id, raw_card_hmac, old_pin, new_pin):
                logging.info("Change pin failed")
                return False
            return True

        except DeviceRemoved:
            logging.info('ATM card was removed!')
            return False
        except NotProvisioned:
            logging.info('ATM card has not been provisioned!')
            return False

    def withdraw(self, pin, amount):
        """Tries to withdraw money from the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN currently associated with the connected
                ATM card
            amount (int): number of bills to withdraw

        Returns:
            list of str: Withdrawn bills on success
            bool: False on failure
        """
        if not self.hsm.inserted():
            logging.info('No hsm inserted')
            return False

        if not isinstance(amount, int):
            logging.info('withdraw: amount must be int')
            return False

        try:
            logging.info('withdraw: Requesting card_id')
            card_id = self.card._get_uuid()

            logging.info('withdraw: Requesting session nonce from bank')
            raw_card_session_nonce = self.bank.get_session_nonce(card_id)

            logging.info('withdraw: Computing HMAC on card')
            raw_card_hmac = self.card.compute_hmac(raw_card_session_nonce)

            # request UUID from HSM if card accepts PIN
            if card_id and raw_card_hmac:
                logging.info('withdraw: Requesting hsm_id from hsm')
                hsm_id, raw_hsm_session_nonce = self.hsm.get_uuid()

                # request withdrawal from bank if HSM gives UUID
                if hsm_id and raw_hsm_session_nonce:
                    logging.info('withdraw: Requesting withdrawal from bank')
                    raw_atm_hmac = self.bank.withdraw(card_id, raw_card_hmac, pin, hsm_id, raw_hsm_session_nonce, amount)

                    if raw_atm_hmac:
                        res = self.hsm.withdraw(raw_atm_hmac, amount)
                        if res:
                            return res
                    return False
            logging.info('withdraw failed')
            return False
        except ValueError:
            logging.info('amount must be an int')
            return False
        except DeviceRemoved:
            logging.info('ATM card was removed!')
            return False
        except NotProvisioned:
            logging.info('ATM card has not been provisioned!')
            return False
