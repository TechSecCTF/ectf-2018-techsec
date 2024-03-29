/***************************************************************************//**
* \file DB_UART_SPI_UART_INT.c
* \version 4.0
*
* \brief
*  This file provides the source code to the Interrupt Service Routine for
*  the SCB Component in SPI and UART modes.
*
* Note:
*
********************************************************************************
* \copyright
* Copyright 2013-2017, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include "DB_UART_PVT.h"
#include "DB_UART_SPI_UART_PVT.h"
#include "cyapicallbacks.h"

#if (DB_UART_SCB_IRQ_INTERNAL)
/*******************************************************************************
* Function Name: DB_UART_SPI_UART_ISR
****************************************************************************//**
*
*  Handles the Interrupt Service Routine for the SCB SPI or UART modes.
*
*******************************************************************************/
CY_ISR(DB_UART_SPI_UART_ISR)
{
#if (DB_UART_INTERNAL_RX_SW_BUFFER_CONST)
    uint32 locHead;
#endif /* (DB_UART_INTERNAL_RX_SW_BUFFER_CONST) */

#if (DB_UART_INTERNAL_TX_SW_BUFFER_CONST)
    uint32 locTail;
#endif /* (DB_UART_INTERNAL_TX_SW_BUFFER_CONST) */

#ifdef DB_UART_SPI_UART_ISR_ENTRY_CALLBACK
    DB_UART_SPI_UART_ISR_EntryCallback();
#endif /* DB_UART_SPI_UART_ISR_ENTRY_CALLBACK */

    if (NULL != DB_UART_customIntrHandler)
    {
        DB_UART_customIntrHandler();
    }

    #if(DB_UART_CHECK_SPI_WAKE_ENABLE)
    {
        /* Clear SPI wakeup source */
        DB_UART_ClearSpiExtClkInterruptSource(DB_UART_INTR_SPI_EC_WAKE_UP);
    }
    #endif

    #if (DB_UART_CHECK_RX_SW_BUFFER)
    {
        if (DB_UART_CHECK_INTR_RX_MASKED(DB_UART_INTR_RX_NOT_EMPTY))
        {
            do
            {
                /* Move local head index */
                locHead = (DB_UART_rxBufferHead + 1u);

                /* Adjust local head index */
                if (DB_UART_INTERNAL_RX_BUFFER_SIZE == locHead)
                {
                    locHead = 0u;
                }

                if (locHead == DB_UART_rxBufferTail)
                {
                    #if (DB_UART_CHECK_UART_RTS_CONTROL_FLOW)
                    {
                        /* There is no space in the software buffer - disable the
                        * RX Not Empty interrupt source. The data elements are
                        * still being received into the RX FIFO until the RTS signal
                        * stops the transmitter. After the data element is read from the
                        * buffer, the RX Not Empty interrupt source is enabled to
                        * move the next data element in the software buffer.
                        */
                        DB_UART_INTR_RX_MASK_REG &= ~DB_UART_INTR_RX_NOT_EMPTY;
                        break;
                    }
                    #else
                    {
                        /* Overflow: through away received data element */
                        (void) DB_UART_RX_FIFO_RD_REG;
                        DB_UART_rxBufferOverflow = (uint8) DB_UART_INTR_RX_OVERFLOW;
                    }
                    #endif
                }
                else
                {
                    /* Store received data */
                    DB_UART_PutWordInRxBuffer(locHead, DB_UART_RX_FIFO_RD_REG);

                    /* Move head index */
                    DB_UART_rxBufferHead = locHead;
                }
            }
            while(0u != DB_UART_GET_RX_FIFO_ENTRIES);

            DB_UART_ClearRxInterruptSource(DB_UART_INTR_RX_NOT_EMPTY);
        }
    }
    #endif


    #if (DB_UART_CHECK_TX_SW_BUFFER)
    {
        if (DB_UART_CHECK_INTR_TX_MASKED(DB_UART_INTR_TX_NOT_FULL))
        {
            do
            {
                /* Check for room in TX software buffer */
                if (DB_UART_txBufferHead != DB_UART_txBufferTail)
                {
                    /* Move local tail index */
                    locTail = (DB_UART_txBufferTail + 1u);

                    /* Adjust local tail index */
                    if (DB_UART_TX_BUFFER_SIZE == locTail)
                    {
                        locTail = 0u;
                    }

                    /* Put data into TX FIFO */
                    DB_UART_TX_FIFO_WR_REG = DB_UART_GetWordFromTxBuffer(locTail);

                    /* Move tail index */
                    DB_UART_txBufferTail = locTail;
                }
                else
                {
                    /* TX software buffer is empty: complete transfer */
                    DB_UART_DISABLE_INTR_TX(DB_UART_INTR_TX_NOT_FULL);
                    break;
                }
            }
            while (DB_UART_SPI_UART_FIFO_SIZE != DB_UART_GET_TX_FIFO_ENTRIES);

            DB_UART_ClearTxInterruptSource(DB_UART_INTR_TX_NOT_FULL);
        }
    }
    #endif

#ifdef DB_UART_SPI_UART_ISR_EXIT_CALLBACK
    DB_UART_SPI_UART_ISR_ExitCallback();
#endif /* DB_UART_SPI_UART_ISR_EXIT_CALLBACK */

}

#endif /* (DB_UART_SCB_IRQ_INTERNAL) */


/* [] END OF FILE */
