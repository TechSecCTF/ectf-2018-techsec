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
#include <strong-arm/random.h>
#include <strong-arm/hmac.h>
#include <stdio.h>

#define PIN_LEN 8
#define UUID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define NONCE_OK "OK"
#define COMPUTE_HMAC '2'
#define GET_UUID '3'

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
static const uint8 BANK_AES_KEY[33] = { 0x00 };


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
    uint8 message[109] = {0x00};
    
    // synchronize with bank
    syncConnection(SYNC_PROV);
 
    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));
        
    // set PIN
    // pullMessage(message);
    // USER_INFO_Write(message, PIN, PIN_LEN);
    // pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // set account number
    pullMessage(message);
    char hex_bank_key[64];
    memcpy(hex_bank_key, message, sizeof(hex_bank_key));

    uint8_t bank_key[32];

    for(int i = 0; i < 32; ++i)
    {
        bank_key[i] = hex2byte(hex_bank_key[2*i], hex_bank_key[2*i + 1]);
    }

    USER_INFO_Write(bank_key, BANK_AES_KEY, sizeof(bank_key));
    USER_INFO_Write(message + sizeof(hex_bank_key), UUID, UUID_LEN);

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
    volatile const uint8 *ptr = PROVISIONED;
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    USER_INFO_Start();
    USB_UART_Start();
    
    // Provision card if on first boot
    // ptr = PROVISIONED;
    if (*ptr == 0x00) {
        provision();
        
        // Mark as provisioned
        i = 0x01;
        USER_INFO_Write(&i,PROVISIONED, 1u);
    }

    // USB_UART_UartPutString("Provisioned!\r\n");
    
    // Go into infinite loop
    while (1) {
               /* Place your application code here. */
        
        // syncronize communication with bank
        syncConnection(SYNC_NORM);

        // get command
        pullMessage(message);
        pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

        if (message[0] == GET_UUID) {
            pushMessage(UUID, UUID_LEN);
        } else if (message[0] == COMPUTE_HMAC) {
            // receive challenge nonce from ATM
            uint8_t nonce[4];
            pullMessage(message);
            memcpy(nonce, message, sizeof(nonce));
            pushMessage((uint8*)NONCE_OK, strlen(NONCE_OK));

            //Send HMAC
            uint8_t hmac_output[32];
            uint8_t hmac_data[40];

            memcpy(hmac_data, UUID, UUID_LEN);
            memcpy(hmac_data + UUID_LEN, nonce, sizeof(nonce));

            HMAC(hmac_output, BANK_AES_KEY, 32, hmac_data, sizeof(hmac_data));

            // Push UUID so that bank can look up AES Key for comm
            pushMessage(hmac_output, sizeof(hmac_output));
        }
    }
}

/* [] END OF FILE */
