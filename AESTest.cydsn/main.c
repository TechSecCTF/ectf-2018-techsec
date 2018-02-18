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
#include <project.h>
#include <strong-arm/aes.h>
#include <stdio.h>

void bytes2hex(uint8_t byte, char* dest)
{
    sprintf(dest, "%02X", byte);
}

int main()
{
    CyGlobalIntEnable;      /* Enable global interrupts */

    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    USB_UART_Start();
//    char key[16] = "abcdefgh12345678";
//    uint8_t plaintext[17];

    for(;;)
    {
        Pin_Blue_Write(1);
//        aes256_encrypt_block(plaintext, key, "AAAAAAAAAAAAAAAA");
//        aes256_encrypt_block(plaintext, key, "BBBBBBBBBBBBBBBB");
//        aes256_encrypt_block(plaintext, key, "CCCCCCCCCCCCCCCC");
        uint32_t unique_id[2];
        CyGetUniqueId(unique_id);

        char id[16];
        for (int i = 0; i < 8; i++){
            bytes2hex(((uint8_t *)unique_id)[i], &id[2*i]);
        }

        USB_UART_UartPutString(id);
        USB_UART_UartPutString("\r\n");
        Pin_Blue_Write(0);
        CyDelay(1000);
    }

    Pin_Glitch_Write(1);
}
