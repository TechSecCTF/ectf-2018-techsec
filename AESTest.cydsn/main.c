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

    for(;;)
    {
       USB_UART_UartPutString("Testing\r\n");
        Pin_Blue_Write(~Pin_Blue_Read());
        CyDelay(500);
    }
}
