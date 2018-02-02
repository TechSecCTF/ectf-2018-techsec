/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/

#include "project.h"
#include <stdlib.h>
#include "usbserialprotocol.h"
#include "SW1.h"
#include "Reset_isr.h"
#include <strong-arm/sha256.h>
#include <strong-arm/aes.h>

#define PIN_LEN 8
#define UUID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define PIN_OK "OK"
#define PIN_BAD "BAD"
#define CHANGE_PIN '3'

//CARD

/* 
 * How to read from EEPROM (persistent memory):
 * 
 * // read variable:
 * static const uint8 EEPROM_BUF_VAR[len] = { val1, val2, ... };
 * // write variable:
 * volatile const uint8 *ptr = EEPROM_BUF_VAR;
 * 
 * uint8 val1 = *ptr;
 * uint8 buf[4] = { 0x01, 0x02, 0x03, 0x04 };
 * USER_INFO_Write(message, EEPROM_BUF_VAR, 4u); 
 */

// global EEPROM read variables
static const uint8 PIN[PIN_LEN] = {0x36, 0x35, 0x34, 0x33, 0x35, 0x34, 0x34, 0x36}; //eCTF
static const uint8 UUID[UUID_LEN] = {0x37, 0x33, 0x36, 0x35, 0x36, 0x33, 0x37, 0x35, 0x37, 0x32, 0x36, 0x39, 0x37, 0x34, 0x37, 0x39}; //security
static const uint8 BANK_AES_KEY[17] = {'b', 'l', 'a', 'n', 'k', ' ', 
                                        'k', 'e', 'y', '!', '!','!','!','!','!','!', 0x00 };
static const uint8 NONCE[5] = {'b', 'l', 'a', 'n', 0x00};


uint8_t hex2byte(char upper_digit, char lower_digit)
{
    uint8_t value = 0;
    
    // Lower nybble.
    if(lower_digit >= '0' && lower_digit <= '9')
    {
        value = lower_digit - '0';
    }
    else if(lower_digit >= 'a' && lower_digit <= 'f')
    {
        value = lower_digit - 'a' + 0xA;
    }
    else if(lower_digit >= 'A' && lower_digit <= 'F')
    {
        value = lower_digit - 'A' + 0xA;
    }
    
    // Upper nybble.
    if(upper_digit >= '0' && upper_digit <= '9')
    {
        value |= (upper_digit - '0') << 4;
    }
    else if(upper_digit >= 'a' && upper_digit <= 'f')
    {
        value |= (upper_digit - 'a' + 0xA) << 4;
    }
    else if(upper_digit >= 'A' && upper_digit <= 'F')
    {
        value |= (upper_digit - 'A' + 0xA) << 4;
    }
    
    // Return result.
    return value;
}

void bytes2hex(uint8_t byte, char* dest)
{       
    sprintf(dest, "%02X", byte);
}


// reset interrupt on button press
CY_ISR(Reset_ISR)
{
    pushMessage((uint8*)"In interrupt\n", strlen("In interrupt\n"));
    SW1_ClearInterrupt();
    CySoftwareReset();
}

// provisions card (should only ever be called once)
void provision()
{
    uint8 message[64];
    
    // synchronize with bank
    syncConnection(SYNC_PROV);
 
    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));
        
    // set PIN
    // pullMessage(message);
    // USER_INFO_Write(message, PIN, PIN_LEN);
    // pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // set account number
    pullMessage(message);
    char hex_bank_key[32];
    char hex_nonce[8];
    memcpy(hex_bank_key, message, 32);
    memcpy(hex_nonce, message+32, 8);

    uint8 bank_key[16];
    uint8 nonce[4];

    for(int i = 0; i < 16; ++i)
    {
        bank_key[i] = hex2byte(hex_bank_key[2*i], hex_bank_key[2*i + 1]);
    }

    for(int i = 0; i < 16; ++i)
    {
        nonce[i] = hex2byte(hex_nonce[2*i], hex_nonce[2*i + 1]);
    }

    USER_INFO_Write(bank_key, BANK_AES_KEY,16);
    USER_INFO_Write(nonce, NONCE, 4);
    USER_INFO_Write(message+40, UUID, UUID_LEN);

    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
}


int main(void)
{
    // enable global interrupts -- DO NOT DELETE
    CyGlobalIntEnable;
    
    // start reset button
    Reset_isr_StartEx(Reset_ISR);
    
    /* Declare vairables here */
    uint8 i;
    uint8 message[128];
    
    // local EEPROM read variable
    static const uint8 PROVISIONED[1] = {0x00};
    
    // EEPROM write variable
    volatile const uint8 *ptr;
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    USER_INFO_Start();
    USB_UART_Start();
    
    // Provision card if on first boot
    ptr = PROVISIONED;
    if (*ptr == 0x00) {
        provision();
        
        // Mark as provisioned
        i = 0x01;
        USER_INFO_Write(&i,PROVISIONED, 1u);
    }
    
    // Go into infinite loop
    while (1) {
               /* Place your application code here. */
        
        // syncronize communication with bank
        syncConnection(SYNC_NORM);
        
        // receive pin number from ATM
        // pullMessage(message);
        
        // if (strncmp((char*)message, (char*)PIN, PIN_LEN)) {
        //     pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        // } else {
        //     pushMessage((uint8*)PIN_OK, strlen(PIN_OK));
            
        // get command
        pullMessage(message);
        pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
        
        // change PIN or broadcast UUID
        // if(message[0] == CHANGE_PIN)
        // {
        //     pullMessage(message);
        //     USER_INFO_Write(message, PIN, PIN_LEN);
            
        //     pushMessage((uint8*)PINCHG_SUC, strlen(PINCHG_SUC));
        // } else {

        //Send encrypted UUID
        // Is the ONLY role of the card now to send its encrypted UUID?
    
        uint8 ciphertext[48];
        // char hex_ciphertext[96];

        uint32_t random_iv = random_uint32();
        aes256_crypt_ctr(ciphertext, BANK_AES_KEY, random_iv, UUID, 36);

        // for (int i = 0; i < 48; i++){
        //     bytes2hex(ciphertext[i], hex_ciphertext[2*i]);
        // }
        
        // pushMessage(hex_ciphertext, 96);  
        

        uint8_t hmac_hash[32];

        uint8_t hmac_data[52];
        memcpy(hmac_data, ciphertext, 48);
        memcpy(hmac_data+48, random_iv, 4);

        HMAC(hmac_hash, BANK_AES_KEY, 16, hmac_data, 52);

        // Maybe ensure that all these messages were received?
        pushMessage(ciphertext, 48);
        pushMessage(random_iv, 4);
        pushMessage(hmac_hash, 32);
    }
}

/* [] END OF FILE */
