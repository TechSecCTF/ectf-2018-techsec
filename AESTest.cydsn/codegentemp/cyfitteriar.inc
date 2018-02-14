;
; File Name: cyfitteriar.inc
; 
; PSoC Creator  4.1 Update 1
;
; Description:
; 
;
;-------------------------------------------------------------------------------
; Copyright (c) 2007-2017 Cypress Semiconductor.  All rights reserved.
; You may use this file only in accordance with the license, terms, conditions, 
; disclaimers, and limitations in the end user license agreement accompanying 
; the software package with which this file was provided.
;-------------------------------------------------------------------------------

#ifndef INCLUDED_CYFITTERIAR_INC
#define INCLUDED_CYFITTERIAR_INC
    INCLUDE cydeviceiar_trm.inc

/* Pin_Blue */
Pin_Blue__0__DM__MASK EQU 0x1C0000
Pin_Blue__0__DM__SHIFT EQU 18
Pin_Blue__0__DR EQU CYREG_PRT1_DR
Pin_Blue__0__HSIOM EQU CYREG_HSIOM_PORT_SEL1
Pin_Blue__0__HSIOM_MASK EQU 0x0F000000
Pin_Blue__0__HSIOM_SHIFT EQU 24
Pin_Blue__0__INTCFG EQU CYREG_PRT1_INTCFG
Pin_Blue__0__INTSTAT EQU CYREG_PRT1_INTSTAT
Pin_Blue__0__MASK EQU 0x40
Pin_Blue__0__PA__CFG0 EQU CYREG_UDB_PA1_CFG0
Pin_Blue__0__PA__CFG1 EQU CYREG_UDB_PA1_CFG1
Pin_Blue__0__PA__CFG10 EQU CYREG_UDB_PA1_CFG10
Pin_Blue__0__PA__CFG11 EQU CYREG_UDB_PA1_CFG11
Pin_Blue__0__PA__CFG12 EQU CYREG_UDB_PA1_CFG12
Pin_Blue__0__PA__CFG13 EQU CYREG_UDB_PA1_CFG13
Pin_Blue__0__PA__CFG14 EQU CYREG_UDB_PA1_CFG14
Pin_Blue__0__PA__CFG2 EQU CYREG_UDB_PA1_CFG2
Pin_Blue__0__PA__CFG3 EQU CYREG_UDB_PA1_CFG3
Pin_Blue__0__PA__CFG4 EQU CYREG_UDB_PA1_CFG4
Pin_Blue__0__PA__CFG5 EQU CYREG_UDB_PA1_CFG5
Pin_Blue__0__PA__CFG6 EQU CYREG_UDB_PA1_CFG6
Pin_Blue__0__PA__CFG7 EQU CYREG_UDB_PA1_CFG7
Pin_Blue__0__PA__CFG8 EQU CYREG_UDB_PA1_CFG8
Pin_Blue__0__PA__CFG9 EQU CYREG_UDB_PA1_CFG9
Pin_Blue__0__PC EQU CYREG_PRT1_PC
Pin_Blue__0__PC2 EQU CYREG_PRT1_PC2
Pin_Blue__0__PORT EQU 1
Pin_Blue__0__PS EQU CYREG_PRT1_PS
Pin_Blue__0__SHIFT EQU 6
Pin_Blue__DR EQU CYREG_PRT1_DR
Pin_Blue__INTCFG EQU CYREG_PRT1_INTCFG
Pin_Blue__INTSTAT EQU CYREG_PRT1_INTSTAT
Pin_Blue__MASK EQU 0x40
Pin_Blue__PA__CFG0 EQU CYREG_UDB_PA1_CFG0
Pin_Blue__PA__CFG1 EQU CYREG_UDB_PA1_CFG1
Pin_Blue__PA__CFG10 EQU CYREG_UDB_PA1_CFG10
Pin_Blue__PA__CFG11 EQU CYREG_UDB_PA1_CFG11
Pin_Blue__PA__CFG12 EQU CYREG_UDB_PA1_CFG12
Pin_Blue__PA__CFG13 EQU CYREG_UDB_PA1_CFG13
Pin_Blue__PA__CFG14 EQU CYREG_UDB_PA1_CFG14
Pin_Blue__PA__CFG2 EQU CYREG_UDB_PA1_CFG2
Pin_Blue__PA__CFG3 EQU CYREG_UDB_PA1_CFG3
Pin_Blue__PA__CFG4 EQU CYREG_UDB_PA1_CFG4
Pin_Blue__PA__CFG5 EQU CYREG_UDB_PA1_CFG5
Pin_Blue__PA__CFG6 EQU CYREG_UDB_PA1_CFG6
Pin_Blue__PA__CFG7 EQU CYREG_UDB_PA1_CFG7
Pin_Blue__PA__CFG8 EQU CYREG_UDB_PA1_CFG8
Pin_Blue__PA__CFG9 EQU CYREG_UDB_PA1_CFG9
Pin_Blue__PC EQU CYREG_PRT1_PC
Pin_Blue__PC2 EQU CYREG_PRT1_PC2
Pin_Blue__PORT EQU 1
Pin_Blue__PS EQU CYREG_PRT1_PS
Pin_Blue__SHIFT EQU 6

/* Pin_Glitch */
Pin_Glitch__0__DM__MASK EQU 0x38000
Pin_Glitch__0__DM__SHIFT EQU 15
Pin_Glitch__0__DR EQU CYREG_PRT1_DR
Pin_Glitch__0__HSIOM EQU CYREG_HSIOM_PORT_SEL1
Pin_Glitch__0__HSIOM_MASK EQU 0x00F00000
Pin_Glitch__0__HSIOM_SHIFT EQU 20
Pin_Glitch__0__INTCFG EQU CYREG_PRT1_INTCFG
Pin_Glitch__0__INTSTAT EQU CYREG_PRT1_INTSTAT
Pin_Glitch__0__MASK EQU 0x20
Pin_Glitch__0__PA__CFG0 EQU CYREG_UDB_PA1_CFG0
Pin_Glitch__0__PA__CFG1 EQU CYREG_UDB_PA1_CFG1
Pin_Glitch__0__PA__CFG10 EQU CYREG_UDB_PA1_CFG10
Pin_Glitch__0__PA__CFG11 EQU CYREG_UDB_PA1_CFG11
Pin_Glitch__0__PA__CFG12 EQU CYREG_UDB_PA1_CFG12
Pin_Glitch__0__PA__CFG13 EQU CYREG_UDB_PA1_CFG13
Pin_Glitch__0__PA__CFG14 EQU CYREG_UDB_PA1_CFG14
Pin_Glitch__0__PA__CFG2 EQU CYREG_UDB_PA1_CFG2
Pin_Glitch__0__PA__CFG3 EQU CYREG_UDB_PA1_CFG3
Pin_Glitch__0__PA__CFG4 EQU CYREG_UDB_PA1_CFG4
Pin_Glitch__0__PA__CFG5 EQU CYREG_UDB_PA1_CFG5
Pin_Glitch__0__PA__CFG6 EQU CYREG_UDB_PA1_CFG6
Pin_Glitch__0__PA__CFG7 EQU CYREG_UDB_PA1_CFG7
Pin_Glitch__0__PA__CFG8 EQU CYREG_UDB_PA1_CFG8
Pin_Glitch__0__PA__CFG9 EQU CYREG_UDB_PA1_CFG9
Pin_Glitch__0__PC EQU CYREG_PRT1_PC
Pin_Glitch__0__PC2 EQU CYREG_PRT1_PC2
Pin_Glitch__0__PORT EQU 1
Pin_Glitch__0__PS EQU CYREG_PRT1_PS
Pin_Glitch__0__SHIFT EQU 5
Pin_Glitch__DR EQU CYREG_PRT1_DR
Pin_Glitch__INTCFG EQU CYREG_PRT1_INTCFG
Pin_Glitch__INTSTAT EQU CYREG_PRT1_INTSTAT
Pin_Glitch__MASK EQU 0x20
Pin_Glitch__PA__CFG0 EQU CYREG_UDB_PA1_CFG0
Pin_Glitch__PA__CFG1 EQU CYREG_UDB_PA1_CFG1
Pin_Glitch__PA__CFG10 EQU CYREG_UDB_PA1_CFG10
Pin_Glitch__PA__CFG11 EQU CYREG_UDB_PA1_CFG11
Pin_Glitch__PA__CFG12 EQU CYREG_UDB_PA1_CFG12
Pin_Glitch__PA__CFG13 EQU CYREG_UDB_PA1_CFG13
Pin_Glitch__PA__CFG14 EQU CYREG_UDB_PA1_CFG14
Pin_Glitch__PA__CFG2 EQU CYREG_UDB_PA1_CFG2
Pin_Glitch__PA__CFG3 EQU CYREG_UDB_PA1_CFG3
Pin_Glitch__PA__CFG4 EQU CYREG_UDB_PA1_CFG4
Pin_Glitch__PA__CFG5 EQU CYREG_UDB_PA1_CFG5
Pin_Glitch__PA__CFG6 EQU CYREG_UDB_PA1_CFG6
Pin_Glitch__PA__CFG7 EQU CYREG_UDB_PA1_CFG7
Pin_Glitch__PA__CFG8 EQU CYREG_UDB_PA1_CFG8
Pin_Glitch__PA__CFG9 EQU CYREG_UDB_PA1_CFG9
Pin_Glitch__PC EQU CYREG_PRT1_PC
Pin_Glitch__PC2 EQU CYREG_PRT1_PC2
Pin_Glitch__PORT EQU 1
Pin_Glitch__PS EQU CYREG_PRT1_PS
Pin_Glitch__SHIFT EQU 5

/* USB_UART */
USB_UART_rx__0__DM__MASK EQU 0x07
USB_UART_rx__0__DM__SHIFT EQU 0
USB_UART_rx__0__DR EQU CYREG_PRT4_DR
USB_UART_rx__0__HSIOM EQU CYREG_HSIOM_PORT_SEL4
USB_UART_rx__0__HSIOM_GPIO EQU 0
USB_UART_rx__0__HSIOM_I2C EQU 14
USB_UART_rx__0__HSIOM_I2C_SCL EQU 14
USB_UART_rx__0__HSIOM_MASK EQU 0x0000000F
USB_UART_rx__0__HSIOM_SHIFT EQU 0
USB_UART_rx__0__HSIOM_SPI EQU 15
USB_UART_rx__0__HSIOM_SPI_MOSI EQU 15
USB_UART_rx__0__HSIOM_UART EQU 9
USB_UART_rx__0__HSIOM_UART_RX EQU 9
USB_UART_rx__0__INTCFG EQU CYREG_PRT4_INTCFG
USB_UART_rx__0__INTSTAT EQU CYREG_PRT4_INTSTAT
USB_UART_rx__0__MASK EQU 0x01
USB_UART_rx__0__PC EQU CYREG_PRT4_PC
USB_UART_rx__0__PC2 EQU CYREG_PRT4_PC2
USB_UART_rx__0__PORT EQU 4
USB_UART_rx__0__PS EQU CYREG_PRT4_PS
USB_UART_rx__0__SHIFT EQU 0
USB_UART_rx__DR EQU CYREG_PRT4_DR
USB_UART_rx__INTCFG EQU CYREG_PRT4_INTCFG
USB_UART_rx__INTSTAT EQU CYREG_PRT4_INTSTAT
USB_UART_rx__MASK EQU 0x01
USB_UART_rx__PC EQU CYREG_PRT4_PC
USB_UART_rx__PC2 EQU CYREG_PRT4_PC2
USB_UART_rx__PORT EQU 4
USB_UART_rx__PS EQU CYREG_PRT4_PS
USB_UART_rx__SHIFT EQU 0
USB_UART_SCB__BIST_CONTROL EQU CYREG_SCB0_BIST_CONTROL
USB_UART_SCB__BIST_DATA EQU CYREG_SCB0_BIST_DATA
USB_UART_SCB__CTRL EQU CYREG_SCB0_CTRL
USB_UART_SCB__EZ_DATA00 EQU CYREG_SCB0_EZ_DATA00
USB_UART_SCB__EZ_DATA01 EQU CYREG_SCB0_EZ_DATA01
USB_UART_SCB__EZ_DATA02 EQU CYREG_SCB0_EZ_DATA02
USB_UART_SCB__EZ_DATA03 EQU CYREG_SCB0_EZ_DATA03
USB_UART_SCB__EZ_DATA04 EQU CYREG_SCB0_EZ_DATA04
USB_UART_SCB__EZ_DATA05 EQU CYREG_SCB0_EZ_DATA05
USB_UART_SCB__EZ_DATA06 EQU CYREG_SCB0_EZ_DATA06
USB_UART_SCB__EZ_DATA07 EQU CYREG_SCB0_EZ_DATA07
USB_UART_SCB__EZ_DATA08 EQU CYREG_SCB0_EZ_DATA08
USB_UART_SCB__EZ_DATA09 EQU CYREG_SCB0_EZ_DATA09
USB_UART_SCB__EZ_DATA10 EQU CYREG_SCB0_EZ_DATA10
USB_UART_SCB__EZ_DATA11 EQU CYREG_SCB0_EZ_DATA11
USB_UART_SCB__EZ_DATA12 EQU CYREG_SCB0_EZ_DATA12
USB_UART_SCB__EZ_DATA13 EQU CYREG_SCB0_EZ_DATA13
USB_UART_SCB__EZ_DATA14 EQU CYREG_SCB0_EZ_DATA14
USB_UART_SCB__EZ_DATA15 EQU CYREG_SCB0_EZ_DATA15
USB_UART_SCB__EZ_DATA16 EQU CYREG_SCB0_EZ_DATA16
USB_UART_SCB__EZ_DATA17 EQU CYREG_SCB0_EZ_DATA17
USB_UART_SCB__EZ_DATA18 EQU CYREG_SCB0_EZ_DATA18
USB_UART_SCB__EZ_DATA19 EQU CYREG_SCB0_EZ_DATA19
USB_UART_SCB__EZ_DATA20 EQU CYREG_SCB0_EZ_DATA20
USB_UART_SCB__EZ_DATA21 EQU CYREG_SCB0_EZ_DATA21
USB_UART_SCB__EZ_DATA22 EQU CYREG_SCB0_EZ_DATA22
USB_UART_SCB__EZ_DATA23 EQU CYREG_SCB0_EZ_DATA23
USB_UART_SCB__EZ_DATA24 EQU CYREG_SCB0_EZ_DATA24
USB_UART_SCB__EZ_DATA25 EQU CYREG_SCB0_EZ_DATA25
USB_UART_SCB__EZ_DATA26 EQU CYREG_SCB0_EZ_DATA26
USB_UART_SCB__EZ_DATA27 EQU CYREG_SCB0_EZ_DATA27
USB_UART_SCB__EZ_DATA28 EQU CYREG_SCB0_EZ_DATA28
USB_UART_SCB__EZ_DATA29 EQU CYREG_SCB0_EZ_DATA29
USB_UART_SCB__EZ_DATA30 EQU CYREG_SCB0_EZ_DATA30
USB_UART_SCB__EZ_DATA31 EQU CYREG_SCB0_EZ_DATA31
USB_UART_SCB__I2C_CFG EQU CYREG_SCB0_I2C_CFG
USB_UART_SCB__I2C_CTRL EQU CYREG_SCB0_I2C_CTRL
USB_UART_SCB__I2C_M_CMD EQU CYREG_SCB0_I2C_M_CMD
USB_UART_SCB__I2C_S_CMD EQU CYREG_SCB0_I2C_S_CMD
USB_UART_SCB__I2C_STATUS EQU CYREG_SCB0_I2C_STATUS
USB_UART_SCB__INTR_CAUSE EQU CYREG_SCB0_INTR_CAUSE
USB_UART_SCB__INTR_I2C_EC EQU CYREG_SCB0_INTR_I2C_EC
USB_UART_SCB__INTR_I2C_EC_MASK EQU CYREG_SCB0_INTR_I2C_EC_MASK
USB_UART_SCB__INTR_I2C_EC_MASKED EQU CYREG_SCB0_INTR_I2C_EC_MASKED
USB_UART_SCB__INTR_M EQU CYREG_SCB0_INTR_M
USB_UART_SCB__INTR_M_MASK EQU CYREG_SCB0_INTR_M_MASK
USB_UART_SCB__INTR_M_MASKED EQU CYREG_SCB0_INTR_M_MASKED
USB_UART_SCB__INTR_M_SET EQU CYREG_SCB0_INTR_M_SET
USB_UART_SCB__INTR_RX EQU CYREG_SCB0_INTR_RX
USB_UART_SCB__INTR_RX_MASK EQU CYREG_SCB0_INTR_RX_MASK
USB_UART_SCB__INTR_RX_MASKED EQU CYREG_SCB0_INTR_RX_MASKED
USB_UART_SCB__INTR_RX_SET EQU CYREG_SCB0_INTR_RX_SET
USB_UART_SCB__INTR_S EQU CYREG_SCB0_INTR_S
USB_UART_SCB__INTR_S_MASK EQU CYREG_SCB0_INTR_S_MASK
USB_UART_SCB__INTR_S_MASKED EQU CYREG_SCB0_INTR_S_MASKED
USB_UART_SCB__INTR_S_SET EQU CYREG_SCB0_INTR_S_SET
USB_UART_SCB__INTR_SPI_EC EQU CYREG_SCB0_INTR_SPI_EC
USB_UART_SCB__INTR_SPI_EC_MASK EQU CYREG_SCB0_INTR_SPI_EC_MASK
USB_UART_SCB__INTR_SPI_EC_MASKED EQU CYREG_SCB0_INTR_SPI_EC_MASKED
USB_UART_SCB__INTR_TX EQU CYREG_SCB0_INTR_TX
USB_UART_SCB__INTR_TX_MASK EQU CYREG_SCB0_INTR_TX_MASK
USB_UART_SCB__INTR_TX_MASKED EQU CYREG_SCB0_INTR_TX_MASKED
USB_UART_SCB__INTR_TX_SET EQU CYREG_SCB0_INTR_TX_SET
USB_UART_SCB__RX_CTRL EQU CYREG_SCB0_RX_CTRL
USB_UART_SCB__RX_FIFO_CTRL EQU CYREG_SCB0_RX_FIFO_CTRL
USB_UART_SCB__RX_FIFO_RD EQU CYREG_SCB0_RX_FIFO_RD
USB_UART_SCB__RX_FIFO_RD_SILENT EQU CYREG_SCB0_RX_FIFO_RD_SILENT
USB_UART_SCB__RX_FIFO_STATUS EQU CYREG_SCB0_RX_FIFO_STATUS
USB_UART_SCB__RX_MATCH EQU CYREG_SCB0_RX_MATCH
USB_UART_SCB__SPI_CTRL EQU CYREG_SCB0_SPI_CTRL
USB_UART_SCB__SPI_STATUS EQU CYREG_SCB0_SPI_STATUS
USB_UART_SCB__SS0_POSISTION EQU 0
USB_UART_SCB__SS1_POSISTION EQU 1
USB_UART_SCB__SS2_POSISTION EQU 2
USB_UART_SCB__SS3_POSISTION EQU 3
USB_UART_SCB__STATUS EQU CYREG_SCB0_STATUS
USB_UART_SCB__TX_CTRL EQU CYREG_SCB0_TX_CTRL
USB_UART_SCB__TX_FIFO_CTRL EQU CYREG_SCB0_TX_FIFO_CTRL
USB_UART_SCB__TX_FIFO_STATUS EQU CYREG_SCB0_TX_FIFO_STATUS
USB_UART_SCB__TX_FIFO_WR EQU CYREG_SCB0_TX_FIFO_WR
USB_UART_SCB__UART_CTRL EQU CYREG_SCB0_UART_CTRL
USB_UART_SCB__UART_RX_CTRL EQU CYREG_SCB0_UART_RX_CTRL
USB_UART_SCB__UART_RX_STATUS EQU CYREG_SCB0_UART_RX_STATUS
USB_UART_SCB__UART_TX_CTRL EQU CYREG_SCB0_UART_TX_CTRL
USB_UART_SCBCLK__DIVIDER_MASK EQU 0x0000FFFF
USB_UART_SCBCLK__ENABLE EQU CYREG_CLK_DIVIDER_A00
USB_UART_SCBCLK__ENABLE_MASK EQU 0x80000000
USB_UART_SCBCLK__MASK EQU 0x80000000
USB_UART_SCBCLK__REGISTER EQU CYREG_CLK_DIVIDER_A00
USB_UART_tx__0__DM__MASK EQU 0x38
USB_UART_tx__0__DM__SHIFT EQU 3
USB_UART_tx__0__DR EQU CYREG_PRT4_DR
USB_UART_tx__0__HSIOM EQU CYREG_HSIOM_PORT_SEL4
USB_UART_tx__0__HSIOM_GPIO EQU 0
USB_UART_tx__0__HSIOM_I2C EQU 14
USB_UART_tx__0__HSIOM_I2C_SDA EQU 14
USB_UART_tx__0__HSIOM_MASK EQU 0x000000F0
USB_UART_tx__0__HSIOM_SHIFT EQU 4
USB_UART_tx__0__HSIOM_SPI EQU 15
USB_UART_tx__0__HSIOM_SPI_MISO EQU 15
USB_UART_tx__0__HSIOM_UART EQU 9
USB_UART_tx__0__HSIOM_UART_TX EQU 9
USB_UART_tx__0__INTCFG EQU CYREG_PRT4_INTCFG
USB_UART_tx__0__INTSTAT EQU CYREG_PRT4_INTSTAT
USB_UART_tx__0__MASK EQU 0x02
USB_UART_tx__0__PC EQU CYREG_PRT4_PC
USB_UART_tx__0__PC2 EQU CYREG_PRT4_PC2
USB_UART_tx__0__PORT EQU 4
USB_UART_tx__0__PS EQU CYREG_PRT4_PS
USB_UART_tx__0__SHIFT EQU 1
USB_UART_tx__DR EQU CYREG_PRT4_DR
USB_UART_tx__INTCFG EQU CYREG_PRT4_INTCFG
USB_UART_tx__INTSTAT EQU CYREG_PRT4_INTSTAT
USB_UART_tx__MASK EQU 0x02
USB_UART_tx__PC EQU CYREG_PRT4_PC
USB_UART_tx__PC2 EQU CYREG_PRT4_PC2
USB_UART_tx__PORT EQU 4
USB_UART_tx__PS EQU CYREG_PRT4_PS
USB_UART_tx__SHIFT EQU 1

/* Miscellaneous */
CYDEV_BCLK__HFCLK__HZ EQU 24000000
CYDEV_BCLK__HFCLK__KHZ EQU 24000
CYDEV_BCLK__HFCLK__MHZ EQU 24
CYDEV_BCLK__SYSCLK__HZ EQU 24000000
CYDEV_BCLK__SYSCLK__KHZ EQU 24000
CYDEV_BCLK__SYSCLK__MHZ EQU 24
CYDEV_CHIP_DIE_LEOPARD EQU 1
CYDEV_CHIP_DIE_PSOC4A EQU 16
CYDEV_CHIP_DIE_PSOC5LP EQU 2
CYDEV_CHIP_DIE_PSOC5TM EQU 3
CYDEV_CHIP_DIE_TMA4 EQU 4
CYDEV_CHIP_DIE_UNKNOWN EQU 0
CYDEV_CHIP_FAMILY_FM0P EQU 5
CYDEV_CHIP_FAMILY_FM3 EQU 6
CYDEV_CHIP_FAMILY_FM4 EQU 7
CYDEV_CHIP_FAMILY_PSOC3 EQU 1
CYDEV_CHIP_FAMILY_PSOC4 EQU 2
CYDEV_CHIP_FAMILY_PSOC5 EQU 3
CYDEV_CHIP_FAMILY_PSOC6 EQU 4
CYDEV_CHIP_FAMILY_UNKNOWN EQU 0
CYDEV_CHIP_FAMILY_USED EQU CYDEV_CHIP_FAMILY_PSOC4
CYDEV_CHIP_JTAG_ID EQU 0x04C81193
CYDEV_CHIP_MEMBER_3A EQU 1
CYDEV_CHIP_MEMBER_4A EQU 16
CYDEV_CHIP_MEMBER_4D EQU 12
CYDEV_CHIP_MEMBER_4E EQU 6
CYDEV_CHIP_MEMBER_4F EQU 17
CYDEV_CHIP_MEMBER_4G EQU 4
CYDEV_CHIP_MEMBER_4H EQU 15
CYDEV_CHIP_MEMBER_4I EQU 21
CYDEV_CHIP_MEMBER_4J EQU 13
CYDEV_CHIP_MEMBER_4K EQU 14
CYDEV_CHIP_MEMBER_4L EQU 20
CYDEV_CHIP_MEMBER_4M EQU 19
CYDEV_CHIP_MEMBER_4N EQU 9
CYDEV_CHIP_MEMBER_4O EQU 7
CYDEV_CHIP_MEMBER_4P EQU 18
CYDEV_CHIP_MEMBER_4Q EQU 11
CYDEV_CHIP_MEMBER_4R EQU 8
CYDEV_CHIP_MEMBER_4S EQU 10
CYDEV_CHIP_MEMBER_4U EQU 5
CYDEV_CHIP_MEMBER_5A EQU 3
CYDEV_CHIP_MEMBER_5B EQU 2
CYDEV_CHIP_MEMBER_6A EQU 22
CYDEV_CHIP_MEMBER_FM3 EQU 26
CYDEV_CHIP_MEMBER_FM4 EQU 27
CYDEV_CHIP_MEMBER_PDL_FM0P_TYPE1 EQU 23
CYDEV_CHIP_MEMBER_PDL_FM0P_TYPE2 EQU 24
CYDEV_CHIP_MEMBER_PDL_FM0P_TYPE3 EQU 25
CYDEV_CHIP_MEMBER_UNKNOWN EQU 0
CYDEV_CHIP_MEMBER_USED EQU CYDEV_CHIP_MEMBER_4A
CYDEV_CHIP_DIE_EXPECT EQU CYDEV_CHIP_MEMBER_USED
CYDEV_CHIP_DIE_ACTUAL EQU CYDEV_CHIP_DIE_EXPECT
CYDEV_CHIP_REV_LEOPARD_ES1 EQU 0
CYDEV_CHIP_REV_LEOPARD_ES2 EQU 1
CYDEV_CHIP_REV_LEOPARD_ES3 EQU 3
CYDEV_CHIP_REV_LEOPARD_PRODUCTION EQU 3
CYDEV_CHIP_REV_PSOC4A_ES0 EQU 17
CYDEV_CHIP_REV_PSOC4A_PRODUCTION EQU 17
CYDEV_CHIP_REV_PSOC5LP_ES0 EQU 0
CYDEV_CHIP_REV_PSOC5LP_PRODUCTION EQU 0
CYDEV_CHIP_REV_PSOC5TM_ES0 EQU 0
CYDEV_CHIP_REV_PSOC5TM_ES1 EQU 1
CYDEV_CHIP_REV_PSOC5TM_PRODUCTION EQU 1
CYDEV_CHIP_REV_TMA4_ES EQU 17
CYDEV_CHIP_REV_TMA4_ES2 EQU 33
CYDEV_CHIP_REV_TMA4_PRODUCTION EQU 17
CYDEV_CHIP_REVISION_3A_ES1 EQU 0
CYDEV_CHIP_REVISION_3A_ES2 EQU 1
CYDEV_CHIP_REVISION_3A_ES3 EQU 3
CYDEV_CHIP_REVISION_3A_PRODUCTION EQU 3
CYDEV_CHIP_REVISION_4A_ES0 EQU 17
CYDEV_CHIP_REVISION_4A_PRODUCTION EQU 17
CYDEV_CHIP_REVISION_4D_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4E_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4F_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4F_PRODUCTION_256DMA EQU 0
CYDEV_CHIP_REVISION_4F_PRODUCTION_256K EQU 0
CYDEV_CHIP_REVISION_4G_ES EQU 17
CYDEV_CHIP_REVISION_4G_ES2 EQU 33
CYDEV_CHIP_REVISION_4G_PRODUCTION EQU 17
CYDEV_CHIP_REVISION_4H_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4I_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4J_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4K_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4L_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4M_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4N_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4O_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4P_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4Q_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4R_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4S_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_4U_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_5A_ES0 EQU 0
CYDEV_CHIP_REVISION_5A_ES1 EQU 1
CYDEV_CHIP_REVISION_5A_PRODUCTION EQU 1
CYDEV_CHIP_REVISION_5B_ES0 EQU 0
CYDEV_CHIP_REVISION_5B_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_6A_NO_UDB EQU 0
CYDEV_CHIP_REVISION_6A_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_FM3_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_FM4_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_PDL_FM0P_TYPE1_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_PDL_FM0P_TYPE2_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_PDL_FM0P_TYPE3_PRODUCTION EQU 0
CYDEV_CHIP_REVISION_USED EQU CYDEV_CHIP_REVISION_4A_PRODUCTION
CYDEV_CHIP_REV_EXPECT EQU CYDEV_CHIP_REVISION_USED
CYDEV_CONFIG_READ_ACCELERATOR EQU 1
CYDEV_CONFIG_UNUSED_IO_AllowButWarn EQU 0
CYDEV_CONFIG_UNUSED_IO_AllowWithInfo EQU 1
CYDEV_CONFIG_UNUSED_IO_Disallowed EQU 2
CYDEV_CONFIG_UNUSED_IO EQU CYDEV_CONFIG_UNUSED_IO_Disallowed
CYDEV_CONFIGURATION_COMPRESSED EQU 1
CYDEV_CONFIGURATION_MODE_COMPRESSED EQU 0
CYDEV_CONFIGURATION_MODE EQU CYDEV_CONFIGURATION_MODE_COMPRESSED
CYDEV_CONFIGURATION_MODE_DMA EQU 2
CYDEV_CONFIGURATION_MODE_UNCOMPRESSED EQU 1
CYDEV_DEBUG_PROTECT_KILL EQU 4
CYDEV_DEBUG_PROTECT_OPEN EQU 1
CYDEV_DEBUG_PROTECT EQU CYDEV_DEBUG_PROTECT_OPEN
CYDEV_DEBUG_PROTECT_PROTECTED EQU 2
CYDEV_DEBUGGING_DPS_Disable EQU 3
CYDEV_DEBUGGING_DPS_SWD EQU 2
CYDEV_DEBUGGING_DPS EQU CYDEV_DEBUGGING_DPS_SWD
CYDEV_DEBUGGING_ENABLE EQU 1
CYDEV_DFT_SELECT_CLK0 EQU 1
CYDEV_DFT_SELECT_CLK1 EQU 2
CYDEV_HEAP_SIZE EQU 0x80
CYDEV_IMO_TRIMMED_BY_USB EQU 0
CYDEV_IMO_TRIMMED_BY_WCO EQU 0
CYDEV_IS_EXPORTING_CODE EQU 0
CYDEV_IS_IMPORTING_CODE EQU 0
CYDEV_PROJ_TYPE EQU 0
CYDEV_PROJ_TYPE_BOOTLOADER EQU 1
CYDEV_PROJ_TYPE_LAUNCHER EQU 5
CYDEV_PROJ_TYPE_LOADABLE EQU 2
CYDEV_PROJ_TYPE_LOADABLEANDBOOTLOADER EQU 4
CYDEV_PROJ_TYPE_MULTIAPPBOOTLOADER EQU 3
CYDEV_PROJ_TYPE_STANDARD EQU 0
CYDEV_STACK_SIZE EQU 0x0400
CYDEV_USE_BUNDLED_CMSIS EQU 1
CYDEV_VARIABLE_VDDA EQU 1
CYDEV_VDDA_MV EQU 3300
CYDEV_VDDD_MV EQU 3300
CYDEV_WDT_GENERATE_ISR EQU 1
CYIPBLOCK_M0S8_CTBM_VERSION EQU 0
CYIPBLOCK_m0s8cpuss_VERSION EQU 0
CYIPBLOCK_m0s8csd_VERSION EQU 0
CYIPBLOCK_m0s8gpio2_VERSION EQU 0
CYIPBLOCK_m0s8hsiom4a_VERSION EQU 0
CYIPBLOCK_m0s8lcd_VERSION EQU 0
CYIPBLOCK_m0s8lpcomp_VERSION EQU 0
CYIPBLOCK_m0s8pclk_VERSION EQU 0
CYIPBLOCK_m0s8sar_VERSION EQU 0
CYIPBLOCK_m0s8scb_VERSION EQU 0
CYIPBLOCK_m0s8srssv2_VERSION EQU 1
CYIPBLOCK_m0s8tcpwm_VERSION EQU 0
CYIPBLOCK_m0s8udbif_VERSION EQU 0
CYIPBLOCK_S8_GPIO_VERSION EQU 2
CYDEV_BOOTLOADER_ENABLE EQU 0

#endif /* INCLUDED_CYFITTERIAR_INC */