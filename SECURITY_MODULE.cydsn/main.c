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
#include <string.h>
//This is needed for the default communication between the BANK and DISPLAY over the USB-UART
#include "usbserialprotocol.h"
#include "SW1.h"
#include <strong-arm/sha256.h>
#include <strong-arm/aes.h>
#include <stdio.h>


// SECURITY MODULE

#define MAX_BILLS 128
#define BILL_LEN 16
#define UUID_LEN 36
#define PROV_MSG "P"
#define WITH_OK "K"
#define WITH_BAD "BAD"
#define RECV_OK "K"
#define EMPTY "EMPTY"
#define EMPTY_BILL "*****EMPTY*****"

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
static const uint8 MONEY[MAX_BILLS][BILL_LEN] = {EMPTY_BILL};
static const uint8 UUID[UUID_LEN + 1] = {'b', 'l', 'a', 'n', 'k', ' ', 
                                        'u', 'u', 'i', 'd', '!', 0x00 };
static const uint8 BANK_AES_KEY[17] = {'b', 'l', 'a', 'n', 'k', ' ', 
                                        'k', 'e', 'y', '!', '!','!','!','!','!','!', 0x00 };
static const uint8 NONCE[5] = {'b', 'l', 'a', 'n', 0x00};
static const uint8 BILLS_LEFT[1] = {0x00};


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


// provisions HSM (should only ever be called once)
void provision()
{
    int i;
    uint8 message[109] = {0x00}
    uint8 numbills;
    
    for(i = 0; i < 128; i++) {
        PIGGY_BANK_Write((uint8*)EMPTY_BILL, MONEY[i], BILL_LEN);
    }
    
    // synchronize with atm
    syncConnection(SYNC_PROV);
 
    strcpy((char*)message, PROV_MSG);
    pushMessage(message, (uint8)strlen(PROV_MSG));
    
        
    // Set blob
    pullMessage(message);

    char hex_bank_key[64];
    char hex_nonce[8];
    memcpy(hex_bank_key, message, sizeof(hex_bank_key));
    memcpy(hex_nonce, message + sizeof(hex_bank_key), sizeof(hex_nonce));

    uint8 bank_key[32];
    uint8 nonce[4];

    for(int i = 0; i < 32; ++i)
    {
        bank_key[i] = hex2byte(hex_bank_key[2*i], hex_bank_key[2*i + 1]);
    }

    for(int i = 0; i < 4; ++i)
    {
        nonce[i] = hex2byte(hex_nonce[2*i], hex_nonce[2*i + 1]);
    }

    PIGGY_BANK_Write(bank_key, BANK_AES_KEY, sizeof(bank_key));
    PIGGY_BANK_Write(nonce, NONCE, sizeof(nonce));
    PIGGY_BANK_Write(message + sizeof(hex_bank_key) + sizeof(hex_nonce), UUID, UUID_LEN);

    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // Get numbills
    pullMessage(message);
    numbills = message[0];
    PIGGY_BANK_Write(&numbills, BILLS_LEFT, 1u);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // Load bills
    for (i = 0; i < numbills; i++) {
        pullMessage(message);
        PIGGY_BANK_Write(message, MONEY[i], BILL_LEN);
        pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    }
}


void dispenseBill()
{
    static uint8 stackloc = 0;
    uint8 message[16];
    volatile const uint8* ptr; 
    
    ptr = MONEY[stackloc];
    
    memset(message, 0u, 16);
    memcpy(message, (void*)ptr, BILL_LEN);

    pushMessage(message, BILL_LEN);
    
    PIGGY_BANK_Write((uint8*)EMPTY_BILL, MONEY[stackloc], 16);
    stackloc = (stackloc + 1) % 128;
}


int main(void)
{
    CyGlobalIntEnable; /* Enable global interrupts. */
    
    // start reset button
    Reset_isr_StartEx(Reset_ISR);
    
    /* Declare vairables here */
    
    uint8 numbills, i, bills_left;
    uint8 message[64];
    
    /*
     * Note:
     *  To write to EEPROM, write to static const uint8 []
     *  To read from EEPROM, read from volatile const uint8 * 
     *      set to write variable
     *
     * PSoC EEPROM is very finnicky if this format is not followed
     */
    static const uint8 PROVISIONED[1] = {0x00}; // write variable
    volatile const uint8* ptr = PROVISIONED;    // read variable
    
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    
    PIGGY_BANK_Start();
    DB_UART_Start();
    
    // provision security module on first boot
    if(*ptr == 0x00)
    {
        provision();
        
        // Mark as provisioned
        i = 0x01;
        PIGGY_BANK_Write(&i, PROVISIONED,1u);
    }
    
    // Go into infinite loop
    while (1) {
        /* Place your application code here. */

        // synchronize with bank
        syncConnection(SYNC_NORM);
            
        // send UUID
        ptr = UUID;
        pushMessage((uint8*)ptr, strlen((char*)ptr));
        
        // get returned UUID
        pullMessage(message);
        
        // compare UUID with stored UUID
        if (strcmp((char*)message, (char*)UUID)) {
            pushMessage((uint8*)WITH_BAD, strlen(WITH_BAD));
        } else {
            pushMessage((uint8*)WITH_OK, strlen(WITH_OK));
            
            // get number of bills
            pullMessage(message);
            numbills = message[0];
            
            ptr = BILLS_LEFT;
            if (*ptr < numbills) {
                pushMessage((uint8*)WITH_BAD, strlen(WITH_BAD));
                continue;
            } else {
                pushMessage((uint8*)WITH_OK, strlen(WITH_OK));
                bills_left = *ptr - numbills;
                PIGGY_BANK_Write(&bills_left, BILLS_LEFT, 0x01);
            }
            
            for (i = 0; i < numbills; i++) {
                dispenseBill();
            }
        }
    }
}

/* [] END OF FILE */
