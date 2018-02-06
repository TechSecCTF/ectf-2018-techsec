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

int main()
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    USB_UART_Start();
    char key[16] = "abcdefgh12345678";

    uint8_t plaintext[17];

    for(;;)
    {
        Pin_Blue_Write(1);
        aes256_encrypt_block(plaintext, key, "AAAAAAAAAAAAAAAA");
        aes256_encrypt_block(plaintext, key, "BBBBBBBBBBBBBBBB");
        aes256_encrypt_block(plaintext, key, "CCCCCCCCCCCCCCCC");
        USB_UART_UartPutString("Testing\r\n");
        CyDelay(5);
        Pin_Blue_Write(0);
    }

    Pin_Glitch_Write(1);
}
