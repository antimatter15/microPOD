//Based on https://github.com/Seeed-Studio/PN532
//and https://github.com/don/NDEF
//and various github comments

#include "Arduino.h"

#ifdef ARDUINO_SAMD_VARIANT_COMPLIANCE
    #define SERIAL SerialUSB
#else
    #define SERIAL Serial
#endif

#ifdef DEBUG
#define DMSG(args...)       SERIAL.print(args)
#define DMSG_STR(str)       SERIAL.println(str)
#define DMSG_HEX(num)       SERIAL.print(' '); SERIAL.print((num>>4)&0x0F, HEX); SERIAL.print(num&0x0F, HEX)
#define DMSG_INT(num)       SERIAL.print(' '); SERIAL.print(num)
#else
#define DMSG(args...)
#define DMSG_STR(str)
#define DMSG_HEX(num)
#define DMSG_INT(num)
#endif



#define PN532_PREAMBLE                (0x00)
#define PN532_STARTCODE1              (0x00)
#define PN532_STARTCODE2              (0xFF)
#define PN532_POSTAMBLE               (0x00)

#define PN532_HOSTTOPN532             (0xD4)
#define PN532_PN532TOHOST             (0xD5)

#define PN532_ACK_WAIT_TIME           (10)  // ms, timeout of waiting for ACK

#define PN532_INVALID_ACK             (-1)
#define PN532_TIMEOUT                 (-2)
#define PN532_INVALID_FRAME           (-3)
#define PN532_NO_SPACE                (-4)

#define REVERSE_BITS_ORDER(b)         b = (b & 0xF0) >> 4 | (b & 0x0F) << 4; \
                                      b = (b & 0xCC) >> 2 | (b & 0x33) << 2; \
                                      b = (b & 0xAA) >> 1 | (b & 0x55) << 1

class PN532Interface
{
public:
    virtual void begin() = 0;
    virtual void wakeup() = 0;

    /**
    * @brief    write a command and check ack
    * @param    header  packet header
    * @param    hlen    length of header
    * @param    body    packet body
    * @param    blen    length of body
    * @return   0       success
    *           not 0   failed
    */
    virtual int8_t writeCommand(const uint8_t *header, uint8_t hlen, const uint8_t *body = 0, uint8_t blen = 0) = 0;

    /**
    * @brief    read the response of a command, strip prefix and suffix
    * @param    buf     to contain the response data
    * @param    len     lenght to read
    * @param    timeout max time to wait, 0 means no timeout
    * @return   >=0     length of response without prefix and suffix
    *           <0      failed to read response
    */
    virtual int16_t readResponse(uint8_t buf[], uint8_t len, uint16_t timeout = 1000) = 0;
};


// PN532 Commands
#define PN532_COMMAND_DIAGNOSE              (0x00)
#define PN532_COMMAND_GETFIRMWAREVERSION    (0x02)
#define PN532_COMMAND_GETGENERALSTATUS      (0x04)
#define PN532_COMMAND_READREGISTER          (0x06)
#define PN532_COMMAND_WRITEREGISTER         (0x08)
#define PN532_COMMAND_READGPIO              (0x0C)
#define PN532_COMMAND_WRITEGPIO             (0x0E)
#define PN532_COMMAND_SETSERIALBAUDRATE     (0x10)
#define PN532_COMMAND_SETPARAMETERS         (0x12)
#define PN532_COMMAND_SAMCONFIGURATION      (0x14)
#define PN532_COMMAND_POWERDOWN             (0x16)
#define PN532_COMMAND_RFCONFIGURATION       (0x32)
#define PN532_COMMAND_RFREGULATIONTEST      (0x58)
#define PN532_COMMAND_INJUMPFORDEP          (0x56)
#define PN532_COMMAND_INJUMPFORPSL          (0x46)
#define PN532_COMMAND_INLISTPASSIVETARGET   (0x4A)
#define PN532_COMMAND_INATR                 (0x50)
#define PN532_COMMAND_INPSL                 (0x4E)
#define PN532_COMMAND_INDATAEXCHANGE        (0x40)
#define PN532_COMMAND_INCOMMUNICATETHRU     (0x42)
#define PN532_COMMAND_INDESELECT            (0x44)
#define PN532_COMMAND_INRELEASE             (0x52)
#define PN532_COMMAND_INSELECT              (0x54)
#define PN532_COMMAND_INAUTOPOLL            (0x60)
#define PN532_COMMAND_TGINITASTARGET        (0x8C)
#define PN532_COMMAND_TGSETGENERALBYTES     (0x92)
#define PN532_COMMAND_TGGETDATA             (0x86)
#define PN532_COMMAND_TGSETDATA             (0x8E)
#define PN532_COMMAND_TGSETMETADATA         (0x94)
#define PN532_COMMAND_TGGETINITIATORCOMMAND (0x88)
#define PN532_COMMAND_TGRESPONSETOINITIATOR (0x90)
#define PN532_COMMAND_TGGETTARGETSTATUS     (0x8A)

#define PN532_RESPONSE_INDATAEXCHANGE       (0x41)
#define PN532_RESPONSE_INLISTPASSIVETARGET  (0x4B)


#define PN532_MIFARE_ISO14443A              (0x00)

// Mifare Commands
#define MIFARE_CMD_AUTH_A                   (0x60)
#define MIFARE_CMD_AUTH_B                   (0x61)
#define MIFARE_CMD_READ                     (0x30)
#define MIFARE_CMD_WRITE                    (0xA0)
#define MIFARE_CMD_WRITE_ULTRALIGHT         (0xA2)
#define MIFARE_CMD_TRANSFER                 (0xB0)
#define MIFARE_CMD_DECREMENT                (0xC0)
#define MIFARE_CMD_INCREMENT                (0xC1)
#define MIFARE_CMD_STORE                    (0xC2)

// FeliCa Commands
#define FELICA_CMD_POLLING                  (0x00)
#define FELICA_CMD_REQUEST_SERVICE          (0x02)
#define FELICA_CMD_REQUEST_RESPONSE         (0x04)
#define FELICA_CMD_READ_WITHOUT_ENCRYPTION  (0x06)
#define FELICA_CMD_WRITE_WITHOUT_ENCRYPTION (0x08)
#define FELICA_CMD_REQUEST_SYSTEM_CODE      (0x0C)

// Prefixes for NDEF Records (to identify record type)
#define NDEF_URIPREFIX_NONE                 (0x00)
#define NDEF_URIPREFIX_HTTP_WWWDOT          (0x01)
#define NDEF_URIPREFIX_HTTPS_WWWDOT         (0x02)
#define NDEF_URIPREFIX_HTTP                 (0x03)
#define NDEF_URIPREFIX_HTTPS                (0x04)
#define NDEF_URIPREFIX_TEL                  (0x05)
#define NDEF_URIPREFIX_MAILTO               (0x06)
#define NDEF_URIPREFIX_FTP_ANONAT           (0x07)
#define NDEF_URIPREFIX_FTP_FTPDOT           (0x08)
#define NDEF_URIPREFIX_FTPS                 (0x09)
#define NDEF_URIPREFIX_SFTP                 (0x0A)
#define NDEF_URIPREFIX_SMB                  (0x0B)
#define NDEF_URIPREFIX_NFS                  (0x0C)
#define NDEF_URIPREFIX_FTP                  (0x0D)
#define NDEF_URIPREFIX_DAV                  (0x0E)
#define NDEF_URIPREFIX_NEWS                 (0x0F)
#define NDEF_URIPREFIX_TELNET               (0x10)
#define NDEF_URIPREFIX_IMAP                 (0x11)
#define NDEF_URIPREFIX_RTSP                 (0x12)
#define NDEF_URIPREFIX_URN                  (0x13)
#define NDEF_URIPREFIX_POP                  (0x14)
#define NDEF_URIPREFIX_SIP                  (0x15)
#define NDEF_URIPREFIX_SIPS                 (0x16)
#define NDEF_URIPREFIX_TFTP                 (0x17)
#define NDEF_URIPREFIX_BTSPP                (0x18)
#define NDEF_URIPREFIX_BTL2CAP              (0x19)
#define NDEF_URIPREFIX_BTGOEP               (0x1A)
#define NDEF_URIPREFIX_TCPOBEX              (0x1B)
#define NDEF_URIPREFIX_IRDAOBEX             (0x1C)
#define NDEF_URIPREFIX_FILE                 (0x1D)
#define NDEF_URIPREFIX_URN_EPC_ID           (0x1E)
#define NDEF_URIPREFIX_URN_EPC_TAG          (0x1F)
#define NDEF_URIPREFIX_URN_EPC_PAT          (0x20)
#define NDEF_URIPREFIX_URN_EPC_RAW          (0x21)
#define NDEF_URIPREFIX_URN_EPC              (0x22)
#define NDEF_URIPREFIX_URN_NFC              (0x23)

#define PN532_GPIO_VALIDATIONBIT            (0x80)
#define PN532_GPIO_P30                      (0)
#define PN532_GPIO_P31                      (1)
#define PN532_GPIO_P32                      (2)
#define PN532_GPIO_P33                      (3)
#define PN532_GPIO_P34                      (4)
#define PN532_GPIO_P35                      (5)

// FeliCa consts
#define FELICA_READ_MAX_SERVICE_NUM         16
#define FELICA_READ_MAX_BLOCK_NUM           12 // for typical FeliCa card
#define FELICA_WRITE_MAX_SERVICE_NUM        16
#define FELICA_WRITE_MAX_BLOCK_NUM          10 // for typical FeliCa card
#define FELICA_REQ_SERVICE_MAX_NODE_NUM     32

class PN532
{
public:
    PN532(PN532Interface &interface);

    void begin(void);

    // Generic PN532 functions
    bool SAMConfig(void);
    uint32_t getFirmwareVersion(void);
    uint32_t readRegister(uint16_t reg);
    uint32_t writeRegister(uint16_t reg, uint8_t val);
    bool writeGPIO(uint8_t pinstate);
    uint8_t readGPIO(void);
    bool setPassiveActivationRetries(uint8_t maxRetries);
    bool setRFField(uint8_t autoRFCA, uint8_t rFOnOff);
    bool powerDownMode();

    /**
    * @brief    Init PN532 as a target
    * @param    timeout max time to wait, 0 means no timeout
    * @return   > 0     success
    *           = 0     timeout
    *           < 0     failed
    */
    int8_t tgInitAsTarget(uint16_t timeout = 0);
    int8_t tgInitAsTarget(const uint8_t* command, const uint8_t len, const uint16_t timeout = 0);

    int16_t tgGetData(uint8_t *buf, uint8_t len);
    bool tgSetData(const uint8_t *header, uint8_t hlen, const uint8_t *body = 0, uint8_t blen = 0);

    int16_t inRelease(const uint8_t relevantTarget = 0);

    // ISO14443A functions
    bool inListPassiveTarget();
    bool startPassiveTargetIDDetection(uint8_t cardbaudrate);
    bool readPassiveTargetID(uint8_t cardbaudrate, uint8_t *uid, uint8_t *uidLength, uint16_t timeout = 1000, bool inlist = false);
    bool inDataExchange(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength);
    bool inCommunicateThru(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength);

    // Mifare Classic functions
    bool mifareclassic_IsFirstBlock (uint32_t uiBlock);
    bool mifareclassic_IsTrailerBlock (uint32_t uiBlock);
    uint8_t mifareclassic_AuthenticateBlock (uint8_t *uid, uint8_t uidLen, uint32_t blockNumber, uint8_t keyNumber, uint8_t *keyData);
    uint8_t mifareclassic_ReadDataBlock (uint8_t blockNumber, uint8_t *data);
    uint8_t mifareclassic_WriteDataBlock (uint8_t blockNumber, uint8_t *data);
    uint8_t mifareclassic_FormatNDEF (void);
    uint8_t mifareclassic_WriteNDEFURI (uint8_t sectorNumber, uint8_t uriIdentifier, const char *url);

    // Mifare Ultralight functions
    uint8_t mifareultralight_ReadPage (uint8_t page, uint8_t *buffer);
    uint8_t mifareultralight_WritePage (uint8_t page, uint8_t *buffer);

    // FeliCa Functions
    int8_t felica_Polling(uint16_t systemCode, uint8_t requestCode, uint8_t *idm, uint8_t *pmm, uint16_t *systemCodeResponse, uint16_t timeout=1000);
    int8_t felica_SendCommand (const uint8_t * command, uint8_t commandlength, uint8_t * response, uint8_t * responseLength);
    int8_t felica_RequestService(uint8_t numNode, uint16_t *nodeCodeList, uint16_t *keyVersions) ;
    int8_t felica_RequestResponse(uint8_t *mode);
    int8_t felica_ReadWithoutEncryption (uint8_t numService, const uint16_t *serviceCodeList, uint8_t numBlock, const uint16_t *blockList, uint8_t blockData[][16]);
    int8_t felica_WriteWithoutEncryption (uint8_t numService, const uint16_t *serviceCodeList, uint8_t numBlock, const uint16_t *blockList, uint8_t blockData[][16]);
    int8_t felica_RequestSystemCode(uint8_t *numSystemCode, uint16_t *systemCodeList);
    int8_t felica_Release();

    // Help functions to display formatted text
    static void PrintHex(const uint8_t *data, const uint32_t numBytes);
    static void PrintHexChar(const uint8_t *pbtData, const uint32_t numBytes);

    uint8_t *getBuffer(uint8_t *len) {
        *len = sizeof(pn532_packetbuffer) - 4;
        return pn532_packetbuffer;
    };

private:
    uint8_t _uid[7];  // ISO14443A uid
    uint8_t _uidLen;  // uid len
    uint8_t _key[6];  // Mifare Classic key
    uint8_t inListedTag; // Tg number of inlisted tag.
    uint8_t _felicaIDm[8]; // FeliCa IDm (NFCID2)
    uint8_t _felicaPMm[8]; // FeliCa PMm (PAD)

    uint8_t pn532_packetbuffer[64];

    PN532Interface *_interface;
};


#define HAL(func)   (_interface->func)

PN532::PN532(PN532Interface &interface)
{
    _interface = &interface;
}

/**************************************************************************/
/*!
    @brief  Setups the HW
*/
/**************************************************************************/
void PN532::begin()
{
    HAL(begin)();
    HAL(wakeup)();
}

/**************************************************************************/
/*!
    @brief  Prints a hexadecimal value in plain characters

    @param  data      Pointer to the uint8_t data
    @param  numBytes  Data length in bytes
*/
/**************************************************************************/
void PN532::PrintHex(const uint8_t *data, const uint32_t numBytes)
{
#ifdef ARDUINO
    for (uint8_t i = 0; i < numBytes; i++) {
        if (data[i] < 0x10) {
            SERIAL.print(" 0");
        } else {
            SERIAL.print(' ');
        }
        SERIAL.print(data[i], HEX);
    }
    SERIAL.println("");
#else
    for (uint8_t i = 0; i < numBytes; i++) {
        printf(" %2X", data[i]);
    }
    printf("\n");
#endif
}

/**************************************************************************/
/*!
    @brief  Prints a hexadecimal value in plain characters, along with
            the char equivalents in the following format

            00 00 00 00 00 00  ......

    @param  data      Pointer to the data
    @param  numBytes  Data length in bytes
*/
/**************************************************************************/
void PN532::PrintHexChar(const uint8_t *data, const uint32_t numBytes)
{
#ifdef ARDUINO
    for (uint8_t i = 0; i < numBytes; i++) {
        if (data[i] < 0x10) {
            SERIAL.print(" 0");
        } else {
            SERIAL.print(' ');
        }
        SERIAL.print(data[i], HEX);
    }
    SERIAL.print("    ");
    for (uint8_t i = 0; i < numBytes; i++) {
        char c = data[i];
        if (c <= 0x1f || c > 0x7f) {
            SERIAL.print('.');
        } else {
            SERIAL.print(c);
        }
    }
    SERIAL.println("");
#else
    for (uint8_t i = 0; i < numBytes; i++) {
        printf(" %2X", data[i]);
    }
    printf("    ");
    for (uint8_t i = 0; i < numBytes; i++) {
        char c = data[i];
        if (c <= 0x1f || c > 0x7f) {
            printf(".");
        } else {
            printf("%c", c);
        }
        printf("\n");
    }
#endif
}

/**************************************************************************/
/*!
    @brief  Checks the firmware version of the PN5xx chip

    @returns  The chip's firmware version and ID
*/
/**************************************************************************/
uint32_t PN532::getFirmwareVersion(void)
{
    uint32_t response;

    pn532_packetbuffer[0] = PN532_COMMAND_GETFIRMWAREVERSION;

    if (HAL(writeCommand)(pn532_packetbuffer, 1)) {
        return 0;
    }

    // read data packet
    int16_t status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));
    if (0 > status) {
        return 0;
    }

    response = pn532_packetbuffer[0];
    response <<= 8;
    response |= pn532_packetbuffer[1];
    response <<= 8;
    response |= pn532_packetbuffer[2];
    response <<= 8;
    response |= pn532_packetbuffer[3];

    return response;
}


/**************************************************************************/
/*!
    @brief  Read a PN532 register.

    @param  reg  the 16-bit register address.

    @returns  The register value.
*/
/**************************************************************************/
uint32_t PN532::readRegister(uint16_t reg)
{
    uint32_t response;

    pn532_packetbuffer[0] = PN532_COMMAND_READREGISTER;
    pn532_packetbuffer[1] = (reg >> 8) & 0xFF;
    pn532_packetbuffer[2] = reg & 0xFF;

    if (HAL(writeCommand)(pn532_packetbuffer, 3)) {
        return 0;
    }

    // read data packet
    int16_t status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));
    if (0 > status) {
        return 0;
    }

    response = pn532_packetbuffer[0];

    return response;
}

/**************************************************************************/
/*!
    @brief  Write to a PN532 register.

    @param  reg  the 16-bit register address.
    @param  val  the 8-bit value to write.

    @returns  0 for failure, 1 for success.
*/
/**************************************************************************/
uint32_t PN532::writeRegister(uint16_t reg, uint8_t val)
{
    uint32_t response;

    pn532_packetbuffer[0] = PN532_COMMAND_WRITEREGISTER;
    pn532_packetbuffer[1] = (reg >> 8) & 0xFF;
    pn532_packetbuffer[2] = reg & 0xFF;
    pn532_packetbuffer[3] = val;


    if (HAL(writeCommand)(pn532_packetbuffer, 4)) {
        return 0;
    }

    // read data packet
    int16_t status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));
    if (0 > status) {
        return 0;
    }

    return 1;
}

/**************************************************************************/
/*!
    Writes an 8-bit value that sets the state of the PN532's GPIO pins

    @warning This function is provided exclusively for board testing and
             is dangerous since it will throw an error if any pin other
             than the ones marked "Can be used as GPIO" are modified!  All
             pins that can not be used as GPIO should ALWAYS be left high
             (value = 1) or the system will become unstable and a HW reset
             will be required to recover the PN532.

             pinState[0]  = P30     Can be used as GPIO
             pinState[1]  = P31     Can be used as GPIO
             pinState[2]  = P32     *** RESERVED (Must be 1!) ***
             pinState[3]  = P33     Can be used as GPIO
             pinState[4]  = P34     *** RESERVED (Must be 1!) ***
             pinState[5]  = P35     Can be used as GPIO

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
bool PN532::writeGPIO(uint8_t pinstate)
{
    // Make sure pinstate does not try to toggle P32 or P34
    pinstate |= (1 << PN532_GPIO_P32) | (1 << PN532_GPIO_P34);

    // Fill command buffer
    pn532_packetbuffer[0] = PN532_COMMAND_WRITEGPIO;
    pn532_packetbuffer[1] = PN532_GPIO_VALIDATIONBIT | pinstate;  // P3 Pins
    pn532_packetbuffer[2] = 0x00;    // P7 GPIO Pins (not used ... taken by I2C)

    DMSG("Writing P3 GPIO: ");
    DMSG_HEX(pn532_packetbuffer[1]);
    DMSG("\n");

    // Send the WRITEGPIO command (0x0E)
    if (HAL(writeCommand)(pn532_packetbuffer, 3))
        return 0;

    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/**************************************************************************/
/*!
    Reads the state of the PN532's GPIO pins

    @returns An 8-bit value containing the pin state where:

             pinState[0]  = P30
             pinState[1]  = P31
             pinState[2]  = P32
             pinState[3]  = P33
             pinState[4]  = P34
             pinState[5]  = P35
*/
/**************************************************************************/
uint8_t PN532::readGPIO(void)
{
    pn532_packetbuffer[0] = PN532_COMMAND_READGPIO;

    // Send the READGPIO command (0x0C)
    if (HAL(writeCommand)(pn532_packetbuffer, 1))
        return 0x0;

    HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));

    /* READGPIO response without prefix and suffix should be in the following format:

      byte            Description
      -------------   ------------------------------------------
      b0              P3 GPIO Pins
      b1              P7 GPIO Pins (not used ... taken by I2C)
      b2              Interface Mode Pins (not used ... bus select pins)
    */


    DMSG("P3 GPIO: "); DMSG_HEX(pn532_packetbuffer[7]);
    DMSG("P7 GPIO: "); DMSG_HEX(pn532_packetbuffer[8]);
    DMSG("I0I1 GPIO: "); DMSG_HEX(pn532_packetbuffer[9]);
    DMSG("\n");

    return pn532_packetbuffer[0];
}

/**************************************************************************/
/*!
    @brief  Configures the SAM (Secure Access Module)
*/
/**************************************************************************/
bool PN532::SAMConfig(void)
{
    pn532_packetbuffer[0] = PN532_COMMAND_SAMCONFIGURATION;
    pn532_packetbuffer[1] = 0x01; // normal mode;
    pn532_packetbuffer[2] = 0x14; // timeout 50ms * 20 = 1 second
    pn532_packetbuffer[3] = 0x01; // use IRQ pin!

    DMSG("SAMConfig\n");

    if (HAL(writeCommand)(pn532_packetbuffer, 4))
        return false;

    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/**************************************************************************/
/*!
    @brief  Turn the module into power mode  will wake up on I2C or SPI request 
*/
/**************************************************************************/
bool PN532::powerDownMode()
{
    pn532_packetbuffer[0] = PN532_COMMAND_POWERDOWN; 
    pn532_packetbuffer[1] = 0xC0; // I2C or SPI Wakeup
    pn532_packetbuffer[2] = 0x00; // no IRQ

    DMSG("POWERDOWN\n");

    if (HAL(writeCommand)(pn532_packetbuffer, 4))
        return false;

    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/**************************************************************************/
/*!
    Sets the MxRtyPassiveActivation uint8_t of the RFConfiguration register

    @param  maxRetries    0xFF to wait forever, 0x00..0xFE to timeout
                          after mxRetries

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
bool PN532::setPassiveActivationRetries(uint8_t maxRetries)
{
    pn532_packetbuffer[0] = PN532_COMMAND_RFCONFIGURATION;
    pn532_packetbuffer[1] = 5;    // Config item 5 (MaxRetries)
    pn532_packetbuffer[2] = 0xFF; // MxRtyATR (default = 0xFF)
    pn532_packetbuffer[3] = 0x01; // MxRtyPSL (default = 0x01)
    pn532_packetbuffer[4] = maxRetries;

    if (HAL(writeCommand)(pn532_packetbuffer, 5))
        return 0x0;  // no ACK

    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/**************************************************************************/
/*!
    Sets the RFon/off uint8_t of the RFConfiguration register

    @param  autoRFCA    0x00 No check of the external field before 
                        activation 
                        
                        0x02 Check the external field before 
                        activation

    @param  rFOnOff     0x00 Switch the RF field off, 0x01 switch the RF 
                        field on

    @returns    1 if everything executed properly, 0 for an error
*/
/**************************************************************************/

bool PN532::setRFField(uint8_t autoRFCA, uint8_t rFOnOff)
{
    pn532_packetbuffer[0] = PN532_COMMAND_RFCONFIGURATION;
    pn532_packetbuffer[1] = 1;
    pn532_packetbuffer[2] = 0x00 | autoRFCA | rFOnOff;  

    if (HAL(writeCommand)(pn532_packetbuffer, 3)) {
        return 0x0;  // command failed
    }

    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/***** ISO14443A Commands ******/

/**************************************************************************/
/*!
    Puts PN532 into passive detection state with IRQ while waiting for an ISO14443A target

    @param  cardBaudRate  Baud rate of the card

    @returns 1 if everything executed properly, 0 for an error
*/
bool PN532::startPassiveTargetIDDetection(uint8_t cardbaudrate) {
    pn532_packetbuffer[0] = PN532_COMMAND_INLISTPASSIVETARGET;
    pn532_packetbuffer[1] = 1; // max 1 cards at once (we can set this to 2 later)
    pn532_packetbuffer[2] = cardbaudrate;

    if (HAL(writeCommand)(pn532_packetbuffer, 3)) {
        return 0x0;  // command failed
    }
}

/**************************************************************************/
/*!
    Waits for an ISO14443A target to enter the field

    @param  cardBaudRate  Baud rate of the card
    @param  uid           Pointer to the array that will be populated
                          with the card's UID (up to 7 bytes)
    @param  uidLength     Pointer to the variable that will hold the
                          length of the card's UID.
    @param  timeout       The number of tries before timing out
    @param  inlist        If set to true, the card will be inlisted

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
bool PN532::readPassiveTargetID(uint8_t cardbaudrate, uint8_t *uid, uint8_t *uidLength, uint16_t timeout, bool inlist)
{
    pn532_packetbuffer[0] = PN532_COMMAND_INLISTPASSIVETARGET;
    pn532_packetbuffer[1] = 1;  // max 1 cards at once (we can set this to 2 later)
    pn532_packetbuffer[2] = cardbaudrate;

    if (HAL(writeCommand)(pn532_packetbuffer, 3)) {
        return 0x0;  // command failed
    }

    // read data packet
    if (HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), timeout) < 0) {
        return 0x0;
    }

    // check some basic stuff
    /* ISO14443A card response should be in the following format:

      byte            Description
      -------------   ------------------------------------------
      b0              Tags Found
      b1              Tag Number (only one used in this example)
      b2..3           SENS_RES
      b4              SEL_RES
      b5              NFCID Length
      b6..NFCIDLen    NFCID
    */

    if (pn532_packetbuffer[0] != 1)
        return 0;

    uint16_t sens_res = pn532_packetbuffer[2];
    sens_res <<= 8;
    sens_res |= pn532_packetbuffer[3];

    DMSG("ATQA: 0x");  DMSG_HEX(sens_res);
    DMSG("SAK: 0x");  DMSG_HEX(pn532_packetbuffer[4]);
    DMSG("\n");

    /* Card appears to be Mifare Classic */
    *uidLength = pn532_packetbuffer[5];

    for (uint8_t i = 0; i < pn532_packetbuffer[5]; i++) {
        uid[i] = pn532_packetbuffer[6 + i];
    }

    if (inlist) {
        inListedTag = pn532_packetbuffer[1];
    }

    return 1;
}


/***** Mifare Classic Functions ******/

/**************************************************************************/
/*!
      Indicates whether the specified block number is the first block
      in the sector (block 0 relative to the current sector)
*/
/**************************************************************************/
bool PN532::mifareclassic_IsFirstBlock (uint32_t uiBlock)
{
    // Test if we are in the small or big sectors
    if (uiBlock < 128)
        return ((uiBlock) % 4 == 0);
    else
        return ((uiBlock) % 16 == 0);
}

/**************************************************************************/
/*!
      Indicates whether the specified block number is the sector trailer
*/
/**************************************************************************/
bool PN532::mifareclassic_IsTrailerBlock (uint32_t uiBlock)
{
    // Test if we are in the small or big sectors
    if (uiBlock < 128)
        return ((uiBlock + 1) % 4 == 0);
    else
        return ((uiBlock + 1) % 16 == 0);
}

/**************************************************************************/
/*!
    Tries to authenticate a block of memory on a MIFARE card using the
    INDATAEXCHANGE command.  See section 7.3.8 of the PN532 User Manual
    for more information on sending MIFARE and other commands.

    @param  uid           Pointer to a byte array containing the card UID
    @param  uidLen        The length (in bytes) of the card's UID (Should
                          be 4 for MIFARE Classic)
    @param  blockNumber   The block number to authenticate.  (0..63 for
                          1KB cards, and 0..255 for 4KB cards).
    @param  keyNumber     Which key type to use during authentication
                          (0 = MIFARE_CMD_AUTH_A, 1 = MIFARE_CMD_AUTH_B)
    @param  keyData       Pointer to a byte array containing the 6 bytes
                          key value

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareclassic_AuthenticateBlock (uint8_t *uid, uint8_t uidLen, uint32_t blockNumber, uint8_t keyNumber, uint8_t *keyData)
{
    uint8_t i;

    // Hang on to the key and uid data
    memcpy (_key, keyData, 6);
    memcpy (_uid, uid, uidLen);
    _uidLen = uidLen;

    // Prepare the authentication command //
    pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;   /* Data Exchange Header */
    pn532_packetbuffer[1] = 1;                              /* Max card numbers */
    pn532_packetbuffer[2] = (keyNumber) ? MIFARE_CMD_AUTH_B : MIFARE_CMD_AUTH_A;
    pn532_packetbuffer[3] = blockNumber;                    /* Block Number (1K = 0..63, 4K = 0..255 */
    memcpy (pn532_packetbuffer + 4, _key, 6);
    for (i = 0; i < _uidLen; i++) {
        pn532_packetbuffer[10 + i] = _uid[i];              /* 4 bytes card ID */
    }

    if (HAL(writeCommand)(pn532_packetbuffer, 10 + _uidLen))
        return 0;

    // Read the response packet
    HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));

    // Check if the response is valid and we are authenticated???
    // for an auth success it should be bytes 5-7: 0xD5 0x41 0x00
    // Mifare auth error is technically byte 7: 0x14 but anything other and 0x00 is not good
    if (pn532_packetbuffer[0] != 0x00) {
        DMSG("Authentification failed\n");
        return 0;
    }

    return 1;
}

/**************************************************************************/
/*!
    Tries to read an entire 16-bytes data block at the specified block
    address.

    @param  blockNumber   The block number to authenticate.  (0..63 for
                          1KB cards, and 0..255 for 4KB cards).
    @param  data          Pointer to the byte array that will hold the
                          retrieved data (if any)

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareclassic_ReadDataBlock (uint8_t blockNumber, uint8_t *data)
{
    DMSG("Trying to read 16 bytes from block ");
    DMSG_INT(blockNumber);

    /* Prepare the command */
    pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
    pn532_packetbuffer[1] = 1;                      /* Card number */
    pn532_packetbuffer[2] = MIFARE_CMD_READ;        /* Mifare Read command = 0x30 */
    pn532_packetbuffer[3] = blockNumber;            /* Block Number (0..63 for 1K, 0..255 for 4K) */

    /* Send the command */
    if (HAL(writeCommand)(pn532_packetbuffer, 4)) {
        return 0;
    }

    /* Read the response packet */
    HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));

    /* If byte 8 isn't 0x00 we probably have an error */
    if (pn532_packetbuffer[0] != 0x00) {
        return 0;
    }

    /* Copy the 16 data bytes to the output buffer        */
    /* Block content starts at byte 9 of a valid response */
    memcpy (data, pn532_packetbuffer + 1, 16);

    return 1;
}

/**************************************************************************/
/*!
    Tries to write an entire 16-bytes data block at the specified block
    address.

    @param  blockNumber   The block number to authenticate.  (0..63 for
                          1KB cards, and 0..255 for 4KB cards).
    @param  data          The byte array that contains the data to write.

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareclassic_WriteDataBlock (uint8_t blockNumber, uint8_t *data)
{
    /* Prepare the first command */
    pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
    pn532_packetbuffer[1] = 1;                      /* Card number */
    pn532_packetbuffer[2] = MIFARE_CMD_WRITE;       /* Mifare Write command = 0xA0 */
    pn532_packetbuffer[3] = blockNumber;            /* Block Number (0..63 for 1K, 0..255 for 4K) */
    memcpy (pn532_packetbuffer + 4, data, 16);        /* Data Payload */

    /* Send the command */
    if (HAL(writeCommand)(pn532_packetbuffer, 20)) {
        return 0;
    }

    /* Read the response packet */
    if (0 > HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer))) {
        return 0;
    }

    /* Check status */
    if (pn532_packetbuffer[0] != 0x00) {
      DMSG("Status code indicates an error: ");
      DMSG_HEX(pn532_packetbuffer[0]);
      DMSG("\n");
        return 0;
    }

    return 1;
}

/**************************************************************************/
/*!
    Formats a Mifare Classic card to store NDEF Records

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareclassic_FormatNDEF (void)
{
    uint8_t sectorbuffer1[16] = {0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
    uint8_t sectorbuffer2[16] = {0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
    uint8_t sectorbuffer3[16] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Note 0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 must be used for key A
    // for the MAD sector in NDEF records (sector 0)

    // Write block 1 and 2 to the card
    if (!(mifareclassic_WriteDataBlock (1, sectorbuffer1)))
        return 0;
    if (!(mifareclassic_WriteDataBlock (2, sectorbuffer2)))
        return 0;
    // Write key A and access rights card
    if (!(mifareclassic_WriteDataBlock (3, sectorbuffer3)))
        return 0;

    // Seems that everything was OK (?!)
    return 1;
}

/**************************************************************************/
/*!
    Writes an NDEF URI Record to the specified sector (1..15)

    Note that this function assumes that the Mifare Classic card is
    already formatted to work as an "NFC Forum Tag" and uses a MAD1
    file system.  You can use the NXP TagWriter app on Android to
    properly format cards for this.

    @param  sectorNumber  The sector that the URI record should be written
                          to (can be 1..15 for a 1K card)
    @param  uriIdentifier The uri identifier code (0 = none, 0x01 =
                          "http://www.", etc.)
    @param  url           The uri text to write (max 38 characters).

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareclassic_WriteNDEFURI (uint8_t sectorNumber, uint8_t uriIdentifier, const char *url)
{
    // Figure out how long the string is
    uint8_t len = strlen(url);

    // Make sure we're within a 1K limit for the sector number
    if ((sectorNumber < 1) || (sectorNumber > 15))
        return 0;

    // Make sure the URI payload is between 1 and 38 chars
    if ((len < 1) || (len > 38))
        return 0;

    // Note 0xD3 0xF7 0xD3 0xF7 0xD3 0xF7 must be used for key A
    // in NDEF records

    // Setup the sector buffer (w/pre-formatted TLV wrapper and NDEF message)
    uint8_t sectorbuffer1[16] = {0x00, 0x00, 0x03, len + 5, 0xD1, 0x01, len + 1, 0x55, uriIdentifier, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sectorbuffer2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sectorbuffer3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sectorbuffer4[16] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (len <= 6) {
        // Unlikely we'll get a url this short, but why not ...
        memcpy (sectorbuffer1 + 9, url, len);
        sectorbuffer1[len + 9] = 0xFE;
    } else if (len == 7) {
        // 0xFE needs to be wrapped around to next block
        memcpy (sectorbuffer1 + 9, url, len);
        sectorbuffer2[0] = 0xFE;
    } else if ((len > 7) && (len <= 22)) {
        // Url fits in two blocks
        memcpy (sectorbuffer1 + 9, url, 7);
        memcpy (sectorbuffer2, url + 7, len - 7);
        sectorbuffer2[len - 7] = 0xFE;
    } else if (len == 23) {
        // 0xFE needs to be wrapped around to final block
        memcpy (sectorbuffer1 + 9, url, 7);
        memcpy (sectorbuffer2, url + 7, len - 7);
        sectorbuffer3[0] = 0xFE;
    } else {
        // Url fits in three blocks
        memcpy (sectorbuffer1 + 9, url, 7);
        memcpy (sectorbuffer2, url + 7, 16);
        memcpy (sectorbuffer3, url + 23, len - 23);
        sectorbuffer3[len - 23] = 0xFE;
    }

    // Now write all three blocks back to the card
    if (!(mifareclassic_WriteDataBlock (sectorNumber * 4, sectorbuffer1)))
        return 0;
    if (!(mifareclassic_WriteDataBlock ((sectorNumber * 4) + 1, sectorbuffer2)))
        return 0;
    if (!(mifareclassic_WriteDataBlock ((sectorNumber * 4) + 2, sectorbuffer3)))
        return 0;
    if (!(mifareclassic_WriteDataBlock ((sectorNumber * 4) + 3, sectorbuffer4)))
        return 0;

    // Seems that everything was OK (?!)
    return 1;
}

/***** Mifare Ultralight Functions ******/

/**************************************************************************/
/*!
    Tries to read an entire 4-bytes page at the specified address.

    @param  page        The page number (0..63 in most cases)
    @param  buffer      Pointer to the byte array that will hold the
                        retrieved data (if any)
*/
/**************************************************************************/
uint8_t PN532::mifareultralight_ReadPage (uint8_t page, uint8_t *buffer)
{
    /* Prepare the command */
    pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
    pn532_packetbuffer[1] = 1;                   /* Card number */
    pn532_packetbuffer[2] = MIFARE_CMD_READ;     /* Mifare Read command = 0x30 */
    pn532_packetbuffer[3] = page;                /* Page Number (0..63 in most cases) */

    /* Send the command */
    if (HAL(writeCommand)(pn532_packetbuffer, 4)) {
        return 0;
    }

    /* Read the response packet */
    HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));

    /* If byte 8 isn't 0x00 we probably have an error */
    if (pn532_packetbuffer[0] == 0x00) {
        /* Copy the 4 data bytes to the output buffer         */
        /* Block content starts at byte 9 of a valid response */
        /* Note that the command actually reads 16 bytes or 4  */
        /* pages at a time ... we simply discard the last 12  */
        /* bytes                                              */
        memcpy (buffer, pn532_packetbuffer + 1, 4);
    } else {
        return 0;
    }

    // Return OK signal
    return 1;
}

/**************************************************************************/
/*!
    Tries to write an entire 4-bytes data buffer at the specified page
    address.

    @param  page     The page number to write into.  (0..63).
    @param  buffer   The byte array that contains the data to write.

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t PN532::mifareultralight_WritePage (uint8_t page, uint8_t *buffer)
{
    /* Prepare the first command */
    pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
    pn532_packetbuffer[1] = 1;                           /* Card number */
    pn532_packetbuffer[2] = MIFARE_CMD_WRITE_ULTRALIGHT; /* Mifare UL Write cmd = 0xA2 */
    pn532_packetbuffer[3] = page;                        /* page Number (0..63) */
    memcpy (pn532_packetbuffer + 4, buffer, 4);          /* Data Payload */

    /* Send the command */
    if (HAL(writeCommand)(pn532_packetbuffer, 8)) {
        return 0;
    }

    /* Read the response packet */
    return (0 < HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer)));
}

/**************************************************************************/
/*!
    @brief  Exchanges an APDU with the currently inlisted peer

    @param  send            Pointer to data to send
    @param  sendLength      Length of the data to send
    @param  response        Pointer to response data
    @param  responseLength  Pointer to the response data length
*/
/**************************************************************************/
bool PN532::inDataExchange(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength)
{
    uint8_t i;

    pn532_packetbuffer[0] = 0x40; // PN532_COMMAND_INDATAEXCHANGE;
    pn532_packetbuffer[1] = inListedTag;

    if (HAL(writeCommand)(pn532_packetbuffer, 2, send, sendLength)) {
        return false;
    }

    int16_t status = HAL(readResponse)(response, *responseLength, 1000);
    if (status < 0) {
        return false;
    }

    if ((response[0] & 0x3f) != 0) {
        DMSG("Status code indicates an error\n");
        return false;
    }

    uint8_t length = status;
    length -= 1;

    if (length > *responseLength) {
        length = *responseLength; // silent truncation...
    }

    for (uint8_t i = 0; i < length; i++) {
        response[i] = response[i + 1];
    }
    *responseLength = length;

    return true;
}

/**************************************************************************/
/*!
    This command is used to support basic data exchanges
    between the PN532 and a target.

    @param  send            Pointer to the command buffer
    @param  sendLength      Command length in bytes
    @param  response        Pointer to response data
    @param  responseLength  Pointer to the response data length
*/
/**************************************************************************/
bool PN532::inCommunicateThru(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength)
{
  pn532_packetbuffer[0] = PN532_COMMAND_INCOMMUNICATETHRU;

  if (HAL(writeCommand)(pn532_packetbuffer, 1, send, sendLength)) {
    return false;
  }

  int16_t status = HAL(readResponse)(response, *responseLength, 1000);
  if (status < 0) {
    return false;
  }

  // check status code
  if (response[0] != 0x0) {
      DMSG("Status code indicates an error : 0x");
      DMSG_HEX(pn532_packetbuffer[0]);
      DMSG("\n");
      return false;
  }

  uint8_t length = status;
  length -= 1;

  if (length > *responseLength) {
      length = *responseLength; // silent truncation...
  }

  for (uint8_t i = 0; i < length; i++) {
    response[i] = response[i + 1];
  }
  *responseLength = length;

  return true;
}

/**************************************************************************/
/*!
    @brief  'InLists' a passive target. PN532 acting as reader/initiator,
            peer acting as card/responder.
*/
/**************************************************************************/
bool PN532::inListPassiveTarget()
{
    pn532_packetbuffer[0] = PN532_COMMAND_INLISTPASSIVETARGET;
    pn532_packetbuffer[1] = 1;
    pn532_packetbuffer[2] = 0;

    DMSG("inList passive target\n");

    if (HAL(writeCommand)(pn532_packetbuffer, 3)) {
        return false;
    }

    int16_t status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), 30000);
    if (status < 0) {
        return false;
    }

    if (pn532_packetbuffer[0] != 1) {
        return false;
    }

    inListedTag = pn532_packetbuffer[1];

    return true;
}

int8_t PN532::tgInitAsTarget(const uint8_t* command, const uint8_t len, const uint16_t timeout){
  
  int8_t status = HAL(writeCommand)(command, len);
    if (status < 0) {
        return -1;
    }

    status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), timeout);
    if (status > 0) {
        return 1;
    } else if (PN532_TIMEOUT == status) {
        return 0;
    } else {
        return -2;
    }
}

/**
 * Peer to Peer
 */
int8_t PN532::tgInitAsTarget(uint16_t timeout)
{
    const uint8_t command[] = {
        PN532_COMMAND_TGINITASTARGET,
        0,
        0x00, 0x00,         //SENS_RES
        0x00, 0x00, 0x00,   //NFCID1
        0x40,               //SEL_RES

        0x01, 0xFE, 0x0F, 0xBB, 0xBA, 0xA6, 0xC9, 0x89, // POL_RES
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF,

        0x01, 0xFE, 0x0F, 0xBB, 0xBA, 0xA6, 0xC9, 0x89, 0x00, 0x00, //NFCID3t: Change this to desired value

        0x0a, 0x46,  0x66, 0x6D, 0x01, 0x01, 0x10, 0x02, 0x02, 0x00, 0x80, // LLCP magic number, version parameter and MIUX
        0x00
    };
    return tgInitAsTarget(command, sizeof(command), timeout);
}

// int16_t PN532::tgGetData(uint8_t *buf, uint8_t len)
// {
//     buf[0] = PN532_COMMAND_TGGETDATA;

//     if (HAL(writeCommand)(buf, 1)) {
//         return -1;
//     }

//     int16_t status = HAL(readResponse)(buf, len, 3000);
//     if (0 >= status) {
//         return status;
//     }

//     uint16_t length = status - 1;


//     if (buf[0] != 0) {
//         DMSG("status is not ok\n");
//         return -5;
//     }

//     for (uint8_t i = 0; i < length; i++) {
//         buf[i] = buf[i + 1];
//     }

//     return length;
// }

int16_t PN532::tgGetData(uint8_t *buf, uint8_t len)
{
    buf[0] = PN532_COMMAND_TGGETDATA;

    if (HAL(writeCommand)(buf, 1)) {
        return -1;
    }

    int16_t status = HAL(readResponse)(buf, len, 3000);
    if (0 >= status) {
        return status;
    }


    uint16_t length = status - 1;

    if(buf[0] == 0x29) {
        DMSG("status 0x29, init again...");
        return -6;
    }
    

    if (buf[0] != 0) {
        DMSG("status is not ok\n");
        return -5;
    }

    for (uint8_t i = 0; i < length; i++) {
        buf[i] = buf[i + 1];
    }

    return length;
}

bool PN532::tgSetData(const uint8_t *header, uint8_t hlen, const uint8_t *body, uint8_t blen)
{
    if (hlen > (sizeof(pn532_packetbuffer) - 1)) {
        if ((body != 0) || (header == pn532_packetbuffer)) {
            DMSG("tgSetData:buffer too small\n");
            return false;
        }

        pn532_packetbuffer[0] = PN532_COMMAND_TGSETDATA;
        if (HAL(writeCommand)(pn532_packetbuffer, 1, header, hlen)) {
            return false;
        }
    } else {
        for (int8_t i = hlen - 1; i >= 0; i--){
            pn532_packetbuffer[i + 1] = header[i];
        }
        pn532_packetbuffer[0] = PN532_COMMAND_TGSETDATA;

        if (HAL(writeCommand)(pn532_packetbuffer, hlen + 1, body, blen)) {
            return false;
        }
    }

    if (0 > HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), 3000)) {
        return false;
    }

    if (0 != pn532_packetbuffer[0]) {
        return false;
    }

    return true;
}

int16_t PN532::inRelease(const uint8_t relevantTarget){

    pn532_packetbuffer[0] = PN532_COMMAND_INRELEASE;
    pn532_packetbuffer[1] = relevantTarget;

    if (HAL(writeCommand)(pn532_packetbuffer, 2)) {
        return 0;
    }

    // read data packet
    return HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer));
}


/***** FeliCa Functions ******/
/**************************************************************************/
/*!
    @brief  Poll FeliCa card. PN532 acting as reader/initiator,
            peer acting as card/responder.
    @param[in]  systemCode             Designation of System Code. When sending FFFFh as System Code,
                                       all FeliCa cards can return response.
    @param[in]  requestCode            Designation of Request Data as follows:
                                         00h: No Request
                                         01h: System Code request (to acquire System Code of the card)
                                         02h: Communication perfomance request
    @param[out] idm                    IDm of the card (8 bytes)
    @param[out] pmm                    PMm of the card (8 bytes)
    @param[out] systemCodeResponse     System Code of the card (Optional, 2bytes)
    @return                            = 1: A FeliCa card has detected
                                       = 0: No card has detected
                                       < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_Polling(uint16_t systemCode, uint8_t requestCode, uint8_t * idm, uint8_t * pmm, uint16_t *systemCodeResponse, uint16_t timeout)
{
  pn532_packetbuffer[0] = PN532_COMMAND_INLISTPASSIVETARGET;
  pn532_packetbuffer[1] = 1;
  pn532_packetbuffer[2] = 1;
  pn532_packetbuffer[3] = FELICA_CMD_POLLING;
  pn532_packetbuffer[4] = (systemCode >> 8) & 0xFF;
  pn532_packetbuffer[5] = systemCode & 0xFF;
  pn532_packetbuffer[6] = requestCode;
  pn532_packetbuffer[7] = 0;

  if (HAL(writeCommand)(pn532_packetbuffer, 8)) {
    DMSG("Could not send Polling command\n");
    return -1;
  }

  int16_t status = HAL(readResponse)(pn532_packetbuffer, 22, timeout);
  if (status < 0) {
    DMSG("Could not receive response\n");
    return -2;
  }

  // Check NbTg (pn532_packetbuffer[7])
  if (pn532_packetbuffer[0] == 0) {
    DMSG("No card had detected\n");
    return 0;
  } else if (pn532_packetbuffer[0] != 1) {
    DMSG("Unhandled number of targets inlisted. NbTg: ");
    DMSG_HEX(pn532_packetbuffer[7]);
    DMSG("\n");
    return -3;
  }

  inListedTag = pn532_packetbuffer[1];
  DMSG("Tag number: ");
  DMSG_HEX(pn532_packetbuffer[1]);
  DMSG("\n");

  // length check
  uint8_t responseLength = pn532_packetbuffer[2];
  if (responseLength != 18 && responseLength != 20) {
    DMSG("Wrong response length\n");
    return -4;
  }

  uint8_t i;
  for (i=0; i<8; ++i) {
    idm[i] = pn532_packetbuffer[4+i];
    _felicaIDm[i] = pn532_packetbuffer[4+i];
    pmm[i] = pn532_packetbuffer[12+i];
    _felicaPMm[i] = pn532_packetbuffer[12+i];
  }

  if ( responseLength == 20 ) {
    *systemCodeResponse = (uint16_t)((pn532_packetbuffer[20] << 8) + pn532_packetbuffer[21]);
  }

  return 1;
}

/**************************************************************************/
/*!
    @brief  Sends FeliCa command to the currently inlisted peer

    @param[in]  command         FeliCa command packet. (e.g. 00 FF FF 00 00  for Polling command)
    @param[in]  commandlength   Length of the FeliCa command packet. (e.g. 0x05 for above Polling command )
    @param[out] response        FeliCa response packet. (e.g. 01 NFCID2(8 bytes) PAD(8 bytes)  for Polling response)
    @param[out] responselength  Length of the FeliCa response packet. (e.g. 0x11 for above Polling command )
    @return                          = 1: Success
                                     < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_SendCommand (const uint8_t *command, uint8_t commandlength, uint8_t *response, uint8_t *responseLength)
{
  if (commandlength > 0xFE) {
    DMSG("Command length too long\n");
    return -1;
  }

  pn532_packetbuffer[0] = 0x40; // PN532_COMMAND_INDATAEXCHANGE;
  pn532_packetbuffer[1] = inListedTag;
  pn532_packetbuffer[2] = commandlength + 1;

  if (HAL(writeCommand)(pn532_packetbuffer, 3, command, commandlength)) {
    DMSG("Could not send FeliCa command\n");
    return -2;
  }

  // Wait card response
  int16_t status = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), 200);
  if (status < 0) {
    DMSG("Could not receive response\n");
    return -3;
  }

  // Check status (pn532_packetbuffer[0])
  if ((pn532_packetbuffer[0] & 0x3F)!=0) {
    DMSG("Status code indicates an error: ");
    DMSG_HEX(pn532_packetbuffer[0]);
    DMSG("\n");
    return -4;
  }

  // length check
  *responseLength = pn532_packetbuffer[1] - 1;
  if ( (status - 2) != *responseLength) {
    DMSG("Wrong response length\n");
    return -5;
  }

  memcpy(response, &pn532_packetbuffer[2], *responseLength);

  return 1;
}


/**************************************************************************/
/*!
    @brief  Sends FeliCa Request Service command

    @param[in]  numNode           length of the nodeCodeList
    @param[in]  nodeCodeList      Node codes(Big Endian)
    @param[out] keyVersions       Key Version of each Node (Big Endian)
    @return                          = 1: Success
                                     < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_RequestService(uint8_t numNode, uint16_t *nodeCodeList, uint16_t *keyVersions)
{
  if (numNode > FELICA_REQ_SERVICE_MAX_NODE_NUM) {
    DMSG("numNode is too large\n");
    return -1;
  }

  uint8_t i, j=0;
  uint8_t cmdLen = 1 + 8 + 1 + 2*numNode;
  uint8_t cmd[cmdLen];
  cmd[j++] = FELICA_CMD_REQUEST_SERVICE;
  for (i=0; i<8; ++i) {
    cmd[j++] = _felicaIDm[i];
  }
  cmd[j++] = numNode;
  for (i=0; i<numNode; ++i) {
    cmd[j++] = nodeCodeList[i] & 0xFF;
    cmd[j++] = (nodeCodeList[i] >> 8) & 0xff;
  }

  uint8_t response[10+2*numNode];
  uint8_t responseLength;

  if (felica_SendCommand(cmd, cmdLen, response, &responseLength) != 1) {
    DMSG("Request Service command failed\n");
    return -2;
  }

  // length check
  if ( responseLength != 10+2*numNode ) {
    DMSG("Request Service command failed (wrong response length)\n");
    return -3;
  }

  for(i=0; i<numNode; i++) {
    keyVersions[i] = (uint16_t)(response[10+i*2] + (response[10+i*2+1] << 8));
  }
  return 1;
}


/**************************************************************************/
/*!
    @brief  Sends FeliCa Request Service command

    @param[out]  mode         Current Mode of the card
    @return                   = 1: Success
                              < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_RequestResponse(uint8_t * mode)
{
  uint8_t cmd[9];
  cmd[0] = FELICA_CMD_REQUEST_RESPONSE;
  memcpy(&cmd[1], _felicaIDm, 8);

  uint8_t response[10];
  uint8_t responseLength;
  if (felica_SendCommand(cmd, 9, response, &responseLength) != 1) {
    DMSG("Request Response command failed\n");
    return -1;
  }

  // length check
  if ( responseLength != 10) {
    DMSG("Request Response command failed (wrong response length)\n");
    return -2;
  }

  *mode = response[9];
  return 1;
}

/**************************************************************************/
/*!
    @brief  Sends FeliCa Read Without Encryption command

    @param[in]  numService         Length of the serviceCodeList
    @param[in]  serviceCodeList    Service Code List (Big Endian)
    @param[in]  numBlock           Length of the blockList
    @param[in]  blockList          Block List (Big Endian, This API only accepts 2-byte block list element)
    @param[out] blockData          Block Data
    @return                        = 1: Success
                                   < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_ReadWithoutEncryption (uint8_t numService, const uint16_t *serviceCodeList, uint8_t numBlock, const uint16_t *blockList, uint8_t blockData[][16])
{
  if (numService > FELICA_READ_MAX_SERVICE_NUM) {
    DMSG("numService is too large\n");
    return -1;
  }
  if (numBlock > FELICA_READ_MAX_BLOCK_NUM) {
    DMSG("numBlock is too large\n");
    return -2;
  }

  uint8_t i, j=0, k;
  uint8_t cmdLen = 1 + 8 + 1 + 2*numService + 1 + 2*numBlock;
  uint8_t cmd[cmdLen];
  cmd[j++] = FELICA_CMD_READ_WITHOUT_ENCRYPTION;
  for (i=0; i<8; ++i) {
    cmd[j++] = _felicaIDm[i];
  }
  cmd[j++] = numService;
  for (i=0; i<numService; ++i) {
    cmd[j++] = serviceCodeList[i] & 0xFF;
    cmd[j++] = (serviceCodeList[i] >> 8) & 0xff;
  }
  cmd[j++] = numBlock;
  for (i=0; i<numBlock; ++i) {
    cmd[j++] = (blockList[i] >> 8) & 0xFF;
    cmd[j++] = blockList[i] & 0xff;
  }

  uint8_t response[12+16*numBlock];
  uint8_t responseLength;
  if (felica_SendCommand(cmd, cmdLen, response, &responseLength) != 1) {
    DMSG("Read Without Encryption command failed\n");
    return -3;
  }

  // length check
  if ( responseLength != 12+16*numBlock ) {
    DMSG("Read Without Encryption command failed (wrong response length)\n");
    return -4;
  }

  // status flag check
  if ( response[9] != 0 || response[10] != 0 ) {
    DMSG("Read Without Encryption command failed (Status Flag: ");
    DMSG_HEX(pn532_packetbuffer[9]);
    DMSG_HEX(pn532_packetbuffer[10]);
    DMSG(")\n");
    return -5;
  }

  k = 12;
  for(i=0; i<numBlock; i++ ) {
    for(j=0; j<16; j++ ) {
      blockData[i][j] = response[k++];
    }
  }

  return 1;
}


/**************************************************************************/
/*!
    @brief  Sends FeliCa Write Without Encryption command

    @param[in]  numService         Length of the serviceCodeList
    @param[in]  serviceCodeList    Service Code List (Big Endian)
    @param[in]  numBlock           Length of the blockList
    @param[in]  blockList          Block List (Big Endian, This API only accepts 2-byte block list element)
    @param[in]  blockData          Block Data (each Block has 16 bytes)
    @return                        = 1: Success
                                   < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_WriteWithoutEncryption (uint8_t numService, const uint16_t *serviceCodeList, uint8_t numBlock, const uint16_t *blockList, uint8_t blockData[][16])
{
  if (numService > FELICA_WRITE_MAX_SERVICE_NUM) {
    DMSG("numService is too large\n");
    return -1;
  }
  if (numBlock > FELICA_WRITE_MAX_BLOCK_NUM) {
    DMSG("numBlock is too large\n");
    return -2;
  }

  uint8_t i, j=0, k;
  uint8_t cmdLen = 1 + 8 + 1 + 2*numService + 1 + 2*numBlock + 16 * numBlock;
  uint8_t cmd[cmdLen];
  cmd[j++] = FELICA_CMD_WRITE_WITHOUT_ENCRYPTION;
  for (i=0; i<8; ++i) {
    cmd[j++] = _felicaIDm[i];
  }
  cmd[j++] = numService;
  for (i=0; i<numService; ++i) {
    cmd[j++] = serviceCodeList[i] & 0xFF;
    cmd[j++] = (serviceCodeList[i] >> 8) & 0xff;
  }
  cmd[j++] = numBlock;
  for (i=0; i<numBlock; ++i) {
    cmd[j++] = (blockList[i] >> 8) & 0xFF;
    cmd[j++] = blockList[i] & 0xff;
  }
  for (i=0; i<numBlock; ++i) {
    for(k=0; k<16; k++) {
      cmd[j++] = blockData[i][k];
    }
  }

  uint8_t response[11];
  uint8_t responseLength;
  if (felica_SendCommand(cmd, cmdLen, response, &responseLength) != 1) {
    DMSG("Write Without Encryption command failed\n");
    return -3;
  }

  // length check
  if ( responseLength != 11 ) {
    DMSG("Write Without Encryption command failed (wrong response length)\n");
    return -4;
  }

  // status flag check
  if ( response[9] != 0 || response[10] != 0 ) {
    DMSG("Write Without Encryption command failed (Status Flag: ");
    DMSG_HEX(pn532_packetbuffer[9]);
    DMSG_HEX(pn532_packetbuffer[10]);
    DMSG(")\n");
    return -5;
  }

  return 1;
}

/**************************************************************************/
/*!
    @brief  Sends FeliCa Request System Code command

    @param[out] numSystemCode        Length of the systemCodeList
    @param[out] systemCodeList       System Code list (Array length should longer than 16)
    @return                          = 1: Success
                                     < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_RequestSystemCode(uint8_t * numSystemCode, uint16_t *systemCodeList)
{
  uint8_t cmd[9];
  cmd[0] = FELICA_CMD_REQUEST_SYSTEM_CODE;
  memcpy(&cmd[1], _felicaIDm, 8);

  uint8_t response[10 + 2 * 16];
  uint8_t responseLength;
  if (felica_SendCommand(cmd, 9, response, &responseLength) != 1) {
    DMSG("Request System Code command failed\n");
    return -1;
  }
  *numSystemCode = response[9];

  // length check
  if ( responseLength < 10 + 2 * *numSystemCode ) {
    DMSG("Request System Code command failed (wrong response length)\n");
    return -2;
  }

  uint8_t i;
  for(i=0; i<*numSystemCode; i++) {
    systemCodeList[i] = (uint16_t)((response[10+i*2]<< 8) + response[10+i*2+1]);
  }

  return 1;
}


/**************************************************************************/
/*!
    @brief  Release FeliCa card
    @return                          = 1: Success
                                     < 0: error
*/
/**************************************************************************/
int8_t PN532::felica_Release()
{
  // InRelease
  pn532_packetbuffer[0] = PN532_COMMAND_INRELEASE;
  pn532_packetbuffer[1] = 0x00;   // All target
  DMSG("Release all FeliCa target\n");

  if (HAL(writeCommand)(pn532_packetbuffer, 2)) {
    DMSG("No ACK\n");
    return -1;  // no ACK
  }

  // Wait card response
  int16_t frameLength = HAL(readResponse)(pn532_packetbuffer, sizeof(pn532_packetbuffer), 1000);
  if (frameLength < 0) {
    DMSG("Could not receive response\n");
    return -2;
  }

  // Check status (pn532_packetbuffer[0])
  if ((pn532_packetbuffer[0] & 0x3F)!=0) {
    DMSG("Status code indicates an error: ");
    DMSG_HEX(pn532_packetbuffer[7]);
    DMSG("\n");
    return -3;
  }

  return 1;
}





#define NDEF_MAX_LENGTH 2048 // altough ndef can handle up to 0xfffe in size, arduino cannot.
typedef enum
{
  COMMAND_COMPLETE,
  TAG_NOT_FOUND,
  FUNCTION_NOT_SUPPORTED,
  MEMORY_FAILURE,
  END_OF_FILE_BEFORE_REACHED_LE_BYTES
} responseCommand;

class EmulateTag
{

public:
  EmulateTag(PN532Interface &interface) : pn532(interface), uidPtr(0), tagWrittenByInitiator(false), tagWriteable(true), updateNdefCallback(0) {}

  bool init();

  bool emulate(const uint16_t tgInitAsTargetTimeout = 0);

  /*
   * @param uid pointer to byte array of length 3 (uid is 4 bytes - first byte is fixed) or zero for uid 
   */
  void setUid(uint8_t *uid = 0);

  void setNdefFile(const uint8_t *ndef, const int16_t ndefLength);

  void getContent(uint8_t **buf, uint16_t *length)
  {
    *buf = ndef_file + 2; // first 2 bytes = length
    *length = (ndef_file[0] << 8) + ndef_file[1];
  }

  bool writeOccured()
  {
    return tagWrittenByInitiator;
  }

  void setTagWriteable(bool setWriteable)
  {
    tagWriteable = setWriteable;
  }

  uint8_t *getNdefFilePtr()
  {
    return ndef_file;
  }

  uint8_t getNdefMaxLength()
  {
    return NDEF_MAX_LENGTH;
  }

  void attach(void (*func)(uint8_t *buf, uint16_t length))
  {
    updateNdefCallback = func;
  };

private:
  PN532 pn532;
  uint8_t ndef_file[NDEF_MAX_LENGTH];
  uint8_t *uidPtr;
  bool tagWrittenByInitiator;
  bool tagWriteable;
  void (*updateNdefCallback)(uint8_t *ndef, uint16_t length);

  void setResponse(responseCommand cmd, uint8_t *buf, uint8_t *sendlen, uint8_t sendlenOffset = 0);
};

#define MAX_TGREAD

// Command APDU
#define C_APDU_CLA 0
#define C_APDU_INS 1  // instruction
#define C_APDU_P1 2   // parameter 1
#define C_APDU_P2 3   // parameter 2
#define C_APDU_LC 4   // length command
#define C_APDU_DATA 5 // data

#define C_APDU_P1_SELECT_BY_ID 0x00
#define C_APDU_P1_SELECT_BY_NAME 0x04

// Response APDU
#define R_APDU_SW1_COMMAND_COMPLETE 0x90
#define R_APDU_SW2_COMMAND_COMPLETE 0x00

#define R_APDU_SW1_NDEF_TAG_NOT_FOUND 0x6a
#define R_APDU_SW2_NDEF_TAG_NOT_FOUND 0x82

#define R_APDU_SW1_FUNCTION_NOT_SUPPORTED 0x6A
#define R_APDU_SW2_FUNCTION_NOT_SUPPORTED 0x81

#define R_APDU_SW1_MEMORY_FAILURE 0x65
#define R_APDU_SW2_MEMORY_FAILURE 0x81

#define R_APDU_SW1_END_OF_FILE_BEFORE_REACHED_LE_BYTES 0x62
#define R_APDU_SW2_END_OF_FILE_BEFORE_REACHED_LE_BYTES 0x82

// ISO7816-4 commands
#define ISO7816_SELECT_FILE 0xA4
#define ISO7816_READ_BINARY 0xB0
#define ISO7816_UPDATE_BINARY 0xD6

typedef enum
{
  NONE,
  CC,
  NDEF
} tag_file; // CC ... Compatibility Container

bool EmulateTag::init()
{
  pn532.begin();
  return pn532.SAMConfig();
}

void EmulateTag::setNdefFile(const uint8_t *ndef, const int16_t ndefLength)
{
  if (ndefLength > (NDEF_MAX_LENGTH - 2))
  {
    DMSG("ndef file too large (> NDEF_MAX_LENGHT -2) - aborting");
    return;
  }

  ndef_file[0] = ndefLength >> 8;
  ndef_file[1] = ndefLength & 0xFF;
  memcpy(ndef_file + 2, ndef, ndefLength);
}

void EmulateTag::setUid(uint8_t *uid)
{
  uidPtr = uid;
}


bool EmulateTag::emulate(const uint16_t tgInitAsTargetTimeout)
{

    //https://github.com/Seeed-Studio/PN532/issues/88
    uint8_t command[] = {
      PN532_COMMAND_TGINITASTARGET,
      0x05,                  // MODE: 0x04 = PICC only, 0x01 = Passive only (0x02 = DEP only)

      // MIFARE PARAMS
      0x04, 0x00,         // SENS_RES (seeeds studio set it to 0x04, nxp to 0x08)
      0x00, 0x00, 0x00,   // NFCID1t  (is set over sketch with setUID())
      0x20,               // SEL_RES    (0x20=Mifare DelFire, 0x60=custom)

      // FELICA PARAMS
      0x01, 0xFE,         // NFCID2t (8 bytes) https://github.com/adafruit/Adafruit-PN532/blob/master/Adafruit_PN532.cpp FeliCa NEEDS TO BEGIN WITH 0x01 0xFE!
      0x05, 0x01, 0x86,
      0x04, 0x02, 0x02,
      0x03, 0x00,         // PAD (8 bytes)
      0x4B, 0x02, 0x4F, 
      0x49, 0x8A, 0x00,   
      0xFF, 0xFF,         // System code (2 bytes)
      
      0x01, 0x01, 0x66,   // NFCID3t (10 bytes)
      0x6D, 0x01, 0x01, 0x10,
      0x02, 0x00, 0x00,

    0x00, // length of general bytes
      0x00  // length of historical bytes
  };
  if (uidPtr != 0)
  { // if uid is set copy 3 bytes to nfcid1
    memcpy(command + 4, uidPtr, 3);
  }

  if (1 != pn532.tgInitAsTarget(command, sizeof(command), tgInitAsTargetTimeout))
  {
    DMSG("tgInitAsTarget failed or timed out!");
    return false;
  }

  uint8_t compatibility_container[] = {
      0, 0x0F,
      0x20,
      0, 0x54,
      0, 0xFF,
      0x04,                                                        // T
      0x06,                                                        // L
      0xE1, 0x04,                                                  // File identifier
      ((NDEF_MAX_LENGTH & 0xFF00) >> 8), (NDEF_MAX_LENGTH & 0xFF), // maximum NDEF file size
      0x00,                                                        // read access 0x0 = granted
      0x00                                                         // write access 0x0 = granted | 0xFF = deny
  };

  if (tagWriteable == false)
  {
    compatibility_container[14] = 0xFF;
  }

  tagWrittenByInitiator = false;

  uint8_t rwbuf[128];
  uint8_t sendlen;
  int16_t status;
  tag_file currentFile = NONE;
  uint16_t cc_size = sizeof(compatibility_container);
  bool runLoop = true;
  bool firstTry = true;
  uint8_t retries = 0;
  uint8_t maxRetries = 3;
  while (runLoop)
  {
    //retry code begins...
    if(retries < maxRetries) {
      retries++;
      status = pn532.tgGetData(rwbuf, sizeof(rwbuf));

      if(status == -6) {
        DMSG("found 0x29, try init again");
        if (1 != pn532.tgInitAsTarget(command, sizeof(command), tgInitAsTargetTimeout))
        {
            DMSG("reset again failed!");
            pn532.inRelease();
            return true;
        }
        DMSG("inited again succesfully");
        retries = maxRetries; // then continue normally by maxing out retries
        continue; 
      }
      if(status < 0) { // some other kind of fail... still retrying
          DMSG("Some other fail, still retrying...");
          continue;
      }
    } else {
        status = pn532.tgGetData(rwbuf, sizeof(rwbuf));
    }

    if (status < 0)
    {
      DMSG("tgGetData failed!\n");
      pn532.inRelease();
      return true;
    }

    uint8_t p1 = rwbuf[C_APDU_P1];
    uint8_t p2 = rwbuf[C_APDU_P2];
    uint8_t lc = rwbuf[C_APDU_LC];
    uint16_t p1p2_length = ((int16_t)p1 << 8) + p2;

    switch (rwbuf[C_APDU_INS])
    {
    case ISO7816_SELECT_FILE:
      DMSG("ISO7816_SELECT_FILE\n");
      switch (p1)
      {
      case C_APDU_P1_SELECT_BY_ID:
        if (p2 != 0x0c)
        {
          DMSG("C_APDU_P2 != 0x0c\n");
          setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
        }
        else if (lc == 2 && rwbuf[C_APDU_DATA] == 0xE1 && (rwbuf[C_APDU_DATA + 1] == 0x03 || rwbuf[C_APDU_DATA + 1] == 0x04))
        {
          setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
          if (rwbuf[C_APDU_DATA + 1] == 0x03)
          {
            currentFile = CC;
          }
          else if (rwbuf[C_APDU_DATA + 1] == 0x04)
          {
            currentFile = NDEF;
          }
        }
        else
        {
          setResponse(TAG_NOT_FOUND, rwbuf, &sendlen);
        }
        break;
      case C_APDU_P1_SELECT_BY_NAME:
        const uint8_t ndef_tag_application_name_v2[] = {0, 0x7, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
        if (0 == memcmp(ndef_tag_application_name_v2, rwbuf + C_APDU_P2, sizeof(ndef_tag_application_name_v2)))
        {
          setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
        }
        else
        {
          DMSG("function not supported\n");
          setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
        }
        break;
      }
      break;
    case ISO7816_READ_BINARY:
      DMSG("ISO7816_READ_BINARY\n");
      switch (currentFile)
      {
      case NONE:
        DMSG("CURRENT_FILE_NONE\n");
        setResponse(TAG_NOT_FOUND, rwbuf, &sendlen);
        break;
      case CC:
        if (p1p2_length > NDEF_MAX_LENGTH)
        {
          DMSG("CC_END_OF_FILE_BEFORE_REACHED_LE_BYTES\n");
          setResponse(END_OF_FILE_BEFORE_REACHED_LE_BYTES, rwbuf, &sendlen);
        }
        else
        {
          DMSG("CC_COPY_BYTES\n");
          memcpy(rwbuf, compatibility_container + p1p2_length, lc);
          setResponse(COMMAND_COMPLETE, rwbuf + lc, &sendlen, lc);
        }
        break;
      case NDEF:
        if (p1p2_length > NDEF_MAX_LENGTH)
        {
          DMSG("NDEF_END_OF_FILE_BEFORE_REACHED_LE_BYTES\n");
          setResponse(END_OF_FILE_BEFORE_REACHED_LE_BYTES, rwbuf, &sendlen);
        }
        else
        {
          DMSG("NDEF_COPY_BYTES\n");
          memcpy(rwbuf, ndef_file + p1p2_length, lc);
          setResponse(COMMAND_COMPLETE, rwbuf + lc, &sendlen, lc);
        }
        break;
      }
      break;
    case ISO7816_UPDATE_BINARY:
      DMSG("ISO7816_UPDATE_BINARY\n");
      if (!tagWriteable)
      {
        setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
      }
      else
      {
        if (p1p2_length > NDEF_MAX_LENGTH)
        {
          setResponse(MEMORY_FAILURE, rwbuf, &sendlen);
        }
        else
        {
          memcpy(ndef_file + p1p2_length, rwbuf + C_APDU_DATA, lc);
          setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
          tagWrittenByInitiator = true;

          uint16_t ndef_length = (ndef_file[0] << 8) + ndef_file[1];
          if ((ndef_length > 0) && (updateNdefCallback != 0))
          {
            updateNdefCallback(ndef_file + 2, ndef_length);
          }
        }
      }
      break;
    default:
      DMSG("Command not supported!");
      DMSG_HEX(rwbuf[C_APDU_INS]);
      DMSG("\n");
      setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
    }
    status = pn532.tgSetData(rwbuf, sendlen);
    if (status < 0)
    {
      DMSG("tgSetData failed\n!");
      pn532.inRelease();
      return true;
    }
  }
  pn532.inRelease();
  return true;
}


void EmulateTag::setResponse(responseCommand cmd, uint8_t *buf, uint8_t *sendlen, uint8_t sendlenOffset)
{
  switch (cmd)
  {
  case COMMAND_COMPLETE:
    buf[0] = R_APDU_SW1_COMMAND_COMPLETE;
    buf[1] = R_APDU_SW2_COMMAND_COMPLETE;
    *sendlen = 2 + sendlenOffset;
    break;
  case TAG_NOT_FOUND:
    buf[0] = R_APDU_SW1_NDEF_TAG_NOT_FOUND;
    buf[1] = R_APDU_SW2_NDEF_TAG_NOT_FOUND;
    *sendlen = 2;
    break;
  case FUNCTION_NOT_SUPPORTED:
    buf[0] = R_APDU_SW1_FUNCTION_NOT_SUPPORTED;
    buf[1] = R_APDU_SW2_FUNCTION_NOT_SUPPORTED;
    *sendlen = 2;
    break;
  case MEMORY_FAILURE:
    buf[0] = R_APDU_SW1_MEMORY_FAILURE;
    buf[1] = R_APDU_SW2_MEMORY_FAILURE;
    *sendlen = 2;
    break;
  case END_OF_FILE_BEFORE_REACHED_LE_BYTES:
    buf[0] = R_APDU_SW1_END_OF_FILE_BEFORE_REACHED_LE_BYTES;
    buf[1] = R_APDU_SW2_END_OF_FILE_BEFORE_REACHED_LE_BYTES;
    *sendlen = 2;
    break;
  }
}


#define PN532_HSU_DEBUG

#define PN532_HSU_READ_TIMEOUT (1000)

class PN532_HSU : public PN532Interface
{
public:
    PN532_HSU(HardwareSerial &serial);

    void begin();
    void wakeup();
    virtual int8_t writeCommand(const uint8_t *header, uint8_t hlen, const uint8_t *body = 0, uint8_t blen = 0);
    int16_t readResponse(uint8_t buf[], uint8_t len, uint16_t timeout);

private:
    HardwareSerial *_serial;
    uint8_t command;

    int8_t readAckFrame();

    int8_t receive(uint8_t *buf, int len, uint16_t timeout = PN532_HSU_READ_TIMEOUT);
};



PN532_HSU::PN532_HSU(HardwareSerial &serial)
{
    _serial = &serial;
    command = 0;
}

void PN532_HSU::begin()
{
    _serial->begin(115200);
}

void PN532_HSU::wakeup()
{
    _serial->write(0x55);
    _serial->write(0x55);
    _serial->write(uint8_t(0x00));
    _serial->write(uint8_t(0x00));
    _serial->write(uint8_t(0x00));

    /** dump serial buffer */
    if (_serial->available())
    {
        DMSG("Dump serial buffer: ");
    }
    while (_serial->available())
    {
        uint8_t ret = _serial->read();
        DMSG_HEX(ret);
    }
}

int8_t PN532_HSU::writeCommand(const uint8_t *header, uint8_t hlen, const uint8_t *body, uint8_t blen)
{

    /** dump serial buffer */
    if (_serial->available())
    {
        DMSG("Dump serial buffer: ");
    }
    while (_serial->available())
    {
        uint8_t ret = _serial->read();
        DMSG_HEX(ret);
    }

    command = header[0];

    _serial->write(uint8_t(PN532_PREAMBLE));
    _serial->write(uint8_t(PN532_STARTCODE1));
    _serial->write(uint8_t(PN532_STARTCODE2));

    uint8_t length = hlen + blen + 1; // length of data field: TFI + DATA
    _serial->write(length);
    _serial->write(~length + 1); // checksum of length

    _serial->write(PN532_HOSTTOPN532);
    uint8_t sum = PN532_HOSTTOPN532; // sum of TFI + DATA

    DMSG("\nWrite: ");

    _serial->write(header, hlen);
    for (uint8_t i = 0; i < hlen; i++)
    {
        sum += header[i];

        DMSG_HEX(header[i]);
    }

    _serial->write(body, blen);
    for (uint8_t i = 0; i < blen; i++)
    {
        sum += body[i];

        DMSG_HEX(body[i]);
    }

    uint8_t checksum = ~sum + 1; // checksum of TFI + DATA
    _serial->write(checksum);
    _serial->write(uint8_t(PN532_POSTAMBLE));

    return readAckFrame();
}

int16_t PN532_HSU::readResponse(uint8_t buf[], uint8_t len, uint16_t timeout)
{
    uint8_t tmp[3];

    DMSG("\nRead:  ");

    /** Frame Preamble and Start Code */
    if (receive(tmp, 3, timeout) <= 0)
    {
        return PN532_TIMEOUT;
    }
    if (0 != tmp[0] || 0 != tmp[1] || 0xFF != tmp[2])
    {
        DMSG("Preamble error");
        return PN532_INVALID_FRAME;
    }

    /** receive length and check */
    uint8_t length[2];
    if (receive(length, 2, timeout) <= 0)
    {
        return PN532_TIMEOUT;
    }
    if (0 != (uint8_t)(length[0] + length[1]))
    {
        DMSG("Length error");
        return PN532_INVALID_FRAME;
    }
    length[0] -= 2;
    if (length[0] > len)
    {
        return PN532_NO_SPACE;
    }

    /** receive command byte */
    uint8_t cmd = command + 1; // response command
    if (receive(tmp, 2, timeout) <= 0)
    {
        return PN532_TIMEOUT;
    }
    if (PN532_PN532TOHOST != tmp[0] || cmd != tmp[1])
    {
        DMSG("Command error");
        return PN532_INVALID_FRAME;
    }

    if (receive(buf, length[0], timeout) != length[0])
    {
        return PN532_TIMEOUT;
    }
    uint8_t sum = PN532_PN532TOHOST + cmd;
    for (uint8_t i = 0; i < length[0]; i++)
    {
        sum += buf[i];
    }

    /** checksum and postamble */
    if (receive(tmp, 2, timeout) <= 0)
    {
        return PN532_TIMEOUT;
    }
    if (0 != (uint8_t)(sum + tmp[0]) || 0 != tmp[1])
    {
        DMSG("Checksum error");
        return PN532_INVALID_FRAME;
    }

    return length[0];
}

int8_t PN532_HSU::readAckFrame()
{
    const uint8_t PN532_ACK[] = {0, 0, 0xFF, 0, 0xFF, 0};
    uint8_t ackBuf[sizeof(PN532_ACK)];

    DMSG("\nAck: ");

    if (receive(ackBuf, sizeof(PN532_ACK), PN532_ACK_WAIT_TIME) <= 0)
    {
        DMSG("Timeout\n");
        return PN532_TIMEOUT;
    }

    if (memcmp(ackBuf, PN532_ACK, sizeof(PN532_ACK)))
    {
        DMSG("Invalid\n");
        return PN532_INVALID_ACK;
    }
    return 0;
}

/**
    @brief receive data .
    @param buf --> return value buffer.
           len --> length expect to receive.
           timeout --> time of reveiving
    @retval number of received bytes, 0 means no data received.
*/
int8_t PN532_HSU::receive(uint8_t *buf, int len, uint16_t timeout)
{
    int read_bytes = 0;
    int ret;
    unsigned long start_millis;

    while (read_bytes < len)
    {
        start_millis = millis();
        do
        {
            ret = _serial->read();
            if (ret >= 0)
            {
                break;
            }
        } while ((timeout == 0) || ((millis() - start_millis) < timeout));

        if (ret < 0)
        {
            if (read_bytes)
            {
                return read_bytes;
            }
            else
            {
                return PN532_TIMEOUT;
            }
            buf[read_bytes] = (uint8_t)ret;
            DMSG_HEX(ret);
            read_bytes++;
        }
        buf[read_bytes] = (uint8_t)ret;
        DMSG_HEX(ret);
        read_bytes++;
    }
    return read_bytes;
}


// To save memory and stop serial output comment out the next line
#define NDEF_USE_SERIAL


#ifdef NDEF_USE_SERIAL
// Borrowed from Adafruit_NFCShield_I2C
void PrintHex(const byte * data, const long numBytes)
{
  int32_t szPos;
  for (szPos=0; szPos < numBytes; szPos++)
  {
    Serial.print("0x");
    // Append leading 0 for small values
    if (data[szPos] <= 0xF)
      Serial.print("0");
    Serial.print(data[szPos]&0xff, HEX);
    if ((numBytes > 1) && (szPos != numBytes - 1))
    {
      Serial.print(" ");
    }
  }
  Serial.println("");
}

// Borrowed from Adafruit_NFCShield_I2C
void PrintHexChar(const byte * data, const long numBytes)
{
  int32_t szPos;
  for (szPos=0; szPos < numBytes; szPos++)
  {
    // Append leading 0 for small values
    if (data[szPos] <= 0xF)
      Serial.print("0");
    Serial.print(data[szPos], HEX);
    if ((numBytes > 1) && (szPos != numBytes - 1))
    {
      Serial.print(" ");
    }
  }
  Serial.print("  ");
  for (szPos=0; szPos < numBytes; szPos++)
  {
    if (data[szPos] <= 0x1F)
      Serial.print(".");
    else
      Serial.print((char)data[szPos]);
  }
  Serial.println("");
}

// Note if buffer % blockSize != 0, last block will not be written
void DumpHex(const byte * data, const long numBytes, const unsigned int blockSize)
{
    int i;
    for (i = 0; i < (numBytes / blockSize); i++)
    {
        PrintHexChar(data, blockSize);
        data += blockSize;
    }
}
#endif


#define TNF_EMPTY 0x0
#define TNF_WELL_KNOWN 0x01
#define TNF_MIME_MEDIA 0x02
#define TNF_ABSOLUTE_URI 0x03
#define TNF_EXTERNAL_TYPE 0x04
#define TNF_UNKNOWN 0x05
#define TNF_UNCHANGED 0x06
#define TNF_RESERVED 0x07

class NdefRecord
{
    public:
        NdefRecord();
        NdefRecord(const NdefRecord& rhs);
        ~NdefRecord();
        NdefRecord& operator=(const NdefRecord& rhs);

        int getEncodedSize();
        void encode(byte *data, bool firstRecord, bool lastRecord);

        unsigned int getTypeLength();
        int getPayloadLength();
        unsigned int getIdLength();

        byte getTnf();
        void getType(byte *type);
        void getPayload(byte *payload);
        void getId(byte *id);

        // convenience methods
        String getType();
        String getId();

        void setTnf(byte tnf);
        void setType(const byte *type, const unsigned int numBytes);
        void setPayload(const byte *payload, const int numBytes);
        void setId(const byte *id, const unsigned int numBytes);

#ifdef NDEF_USE_SERIAL
        void print();
#endif
    private:
        byte getTnfByte(bool firstRecord, bool lastRecord);
        byte _tnf; // 3 bit
        unsigned int _typeLength;
        int _payloadLength;
        unsigned int _idLength;
        byte *_type;
        byte *_payload;
        byte *_id;
};



NdefRecord::NdefRecord()
{
    //Serial.println("NdefRecord Constructor 1");
    _tnf = 0;
    _typeLength = 0;
    _payloadLength = 0;
    _idLength = 0;
    _type = (byte *)NULL;
    _payload = (byte *)NULL;
    _id = (byte *)NULL;
}

NdefRecord::NdefRecord(const NdefRecord& rhs)
{
    //Serial.println("NdefRecord Constructor 2 (copy)");

    _tnf = rhs._tnf;
    _typeLength = rhs._typeLength;
    _payloadLength = rhs._payloadLength;
    _idLength = rhs._idLength;
    _type = (byte *)NULL;
    _payload = (byte *)NULL;
    _id = (byte *)NULL;

    if (_typeLength)
    {
        _type = (byte*)malloc(_typeLength);
        memcpy(_type, rhs._type, _typeLength);
    }

    if (_payloadLength)
    {
        _payload = (byte*)malloc(_payloadLength);
        memcpy(_payload, rhs._payload, _payloadLength);
    }

    if (_idLength)
    {
        _id = (byte*)malloc(_idLength);
        memcpy(_id, rhs._id, _idLength);
    }

}

// TODO NdefRecord::NdefRecord(tnf, type, payload, id)

NdefRecord::~NdefRecord()
{
    //Serial.println("NdefRecord Destructor");
    if (_typeLength)
    {
        free(_type);
    }

    if (_payloadLength)
    {
        free(_payload);
    }

    if (_idLength)
    {
        free(_id);
    }
}

NdefRecord& NdefRecord::operator=(const NdefRecord& rhs)
{
    //Serial.println("NdefRecord ASSIGN");

    if (this != &rhs)
    {
        // free existing
        if (_typeLength)
        {
            free(_type);
        }

        if (_payloadLength)
        {
            free(_payload);
        }

        if (_idLength)
        {
            free(_id);
        }

        _tnf = rhs._tnf;
        _typeLength = rhs._typeLength;
        _payloadLength = rhs._payloadLength;
        _idLength = rhs._idLength;

        if (_typeLength)
        {
            _type = (byte*)malloc(_typeLength);
            memcpy(_type, rhs._type, _typeLength);
        }

        if (_payloadLength)
        {
            _payload = (byte*)malloc(_payloadLength);
            memcpy(_payload, rhs._payload, _payloadLength);
        }

        if (_idLength)
        {
            _id = (byte*)malloc(_idLength);
            memcpy(_id, rhs._id, _idLength);
        }
    }
    return *this;
}

// size of records in bytes
int NdefRecord::getEncodedSize()
{
    int size = 2; // tnf + typeLength
    if (_payloadLength > 0xFF)
    {
        size += 4;
    }
    else
    {
        size += 1;
    }

    if (_idLength)
    {
        size += 1;
    }

    size += (_typeLength + _payloadLength + _idLength);

    return size;
}

void NdefRecord::encode(byte *data, bool firstRecord, bool lastRecord)
{
    // assert data > getEncodedSize()

    uint8_t* data_ptr = &data[0];

    *data_ptr = getTnfByte(firstRecord, lastRecord);
    data_ptr += 1;

    *data_ptr = _typeLength;
    data_ptr += 1;

    if (_payloadLength <= 0xFF) {  // short record
        *data_ptr = _payloadLength;
        data_ptr += 1;
    } else { // long format
        // 4 bytes but we store length as an int
        data_ptr[0] = 0x0; // (_payloadLength >> 24) & 0xFF;
        data_ptr[1] = 0x0; // (_payloadLength >> 16) & 0xFF;
        data_ptr[2] = (_payloadLength >> 8) & 0xFF;
        data_ptr[3] = _payloadLength & 0xFF;
        data_ptr += 4;
    }

    if (_idLength)
    {
        *data_ptr = _idLength;
        data_ptr += 1;
    }

    //Serial.println(2);
    memcpy(data_ptr, _type, _typeLength);
    data_ptr += _typeLength;

    if (_idLength)
    {
        memcpy(data_ptr, _id, _idLength);
        data_ptr += _idLength;
    }
    
    memcpy(data_ptr, _payload, _payloadLength);
    data_ptr += _payloadLength;
}

byte NdefRecord::getTnfByte(bool firstRecord, bool lastRecord)
{
    int value = _tnf;

    if (firstRecord) { // mb
        value = value | 0x80;
    }

    if (lastRecord) { //
        value = value | 0x40;
    }

    // chunked flag is always false for now
    // if (cf) {
    //     value = value | 0x20;
    // }

    if (_payloadLength <= 0xFF) {
        value = value | 0x10;
    }

    if (_idLength) {
        value = value | 0x8;
    }

    return value;
}

byte NdefRecord::getTnf()
{
    return _tnf;
}

void NdefRecord::setTnf(byte tnf)
{
    _tnf = tnf;
}

unsigned int NdefRecord::getTypeLength()
{
    return _typeLength;
}

int NdefRecord::getPayloadLength()
{
    return _payloadLength;
}

unsigned int NdefRecord::getIdLength()
{
    return _idLength;
}

String NdefRecord::getType()
{
    char type[_typeLength + 1];
    memcpy(type, _type, _typeLength);
    type[_typeLength] = '\0'; // null terminate
    return String(type);
}

// this assumes the caller created type correctly
void NdefRecord::getType(uint8_t* type)
{
    memcpy(type, _type, _typeLength);
}

void NdefRecord::setType(const byte * type, const unsigned int numBytes)
{
    if(_typeLength)
    {
        free(_type);
    }

    _type = (uint8_t*)malloc(numBytes);
    memcpy(_type, type, numBytes);
    _typeLength = numBytes;
}

// assumes the caller sized payload properly
void NdefRecord::getPayload(byte *payload)
{
    memcpy(payload, _payload, _payloadLength);
}

void NdefRecord::setPayload(const byte * payload, const int numBytes)
{
    if (_payloadLength)
    {
        free(_payload);
    }

    _payload = (byte*)malloc(numBytes);
    memcpy(_payload, payload, numBytes);
    _payloadLength = numBytes;
}

String NdefRecord::getId()
{
    char id[_idLength + 1];
    memcpy(id, _id, _idLength);
    id[_idLength] = '\0'; // null terminate
    return String(id);
}

void NdefRecord::getId(byte *id)
{
    memcpy(id, _id, _idLength);
}

void NdefRecord::setId(const byte * id, const unsigned int numBytes)
{
    if (_idLength)
    {
        free(_id);
    }

    _id = (byte*)malloc(numBytes);
    memcpy(_id, id, numBytes);
    _idLength = numBytes;
}
#ifdef NDEF_USE_SERIAL

void NdefRecord::print()
{
    Serial.println(F("  NDEF Record"));
    Serial.print(F("    TNF 0x"));Serial.print(_tnf, HEX);Serial.print(" ");
    switch (_tnf) {
    case TNF_EMPTY:
        Serial.println(F("Empty"));
        break;
    case TNF_WELL_KNOWN:
        Serial.println(F("Well Known"));
        break;
    case TNF_MIME_MEDIA:
        Serial.println(F("Mime Media"));
        break;
    case TNF_ABSOLUTE_URI:
        Serial.println(F("Absolute URI"));
        break;
    case TNF_EXTERNAL_TYPE:
        Serial.println(F("External"));
        break;
    case TNF_UNKNOWN:
        Serial.println(F("Unknown"));
        break;
    case TNF_UNCHANGED:
        Serial.println(F("Unchanged"));
        break;
    case TNF_RESERVED:
        Serial.println(F("Reserved"));
        break;
    default:
        Serial.println();
    }
    Serial.print(F("    Type Length 0x"));Serial.print(_typeLength, HEX);Serial.print(" ");Serial.println(_typeLength);
    Serial.print(F("    Payload Length 0x"));Serial.print(_payloadLength, HEX);;Serial.print(" ");Serial.println(_payloadLength);
    if (_idLength)
    {
        Serial.print(F("    Id Length 0x"));Serial.println(_idLength, HEX);
    }
    Serial.print(F("    Type "));PrintHexChar(_type, _typeLength);
    // TODO chunk large payloads so this is readable
    Serial.print(F("    Payload "));PrintHexChar(_payload, _payloadLength);
    if (_idLength)
    {
        Serial.print(F("    Id "));PrintHexChar(_id, _idLength);
    }
    Serial.print(F("    Record is "));Serial.print(getEncodedSize());Serial.println(" bytes");

}
#endif



#define MAX_NDEF_RECORDS 4

class NdefMessage
{
    public:
        NdefMessage(void);
        NdefMessage(const byte *data, const int numBytes);
        NdefMessage(const NdefMessage& rhs);
        ~NdefMessage();
        NdefMessage& operator=(const NdefMessage& rhs);

        int getEncodedSize(); // need so we can pass array to encode
        void encode(byte *data);

        boolean addRecord(NdefRecord& record);
        void addMimeMediaRecord(String mimeType, String payload);
        void addMimeMediaRecord(String mimeType, byte *payload, int payloadLength);
        void addTextRecord(String text);
        void addTextRecord(String text, String encoding);
        void addUriRecord(String uri);
        void addEmptyRecord();

        unsigned int getRecordCount();
        NdefRecord getRecord(int index);
        NdefRecord operator[](int index);

#ifdef NDEF_USE_SERIAL
        void print();
#endif
    private:
        NdefRecord _records[MAX_NDEF_RECORDS];
        unsigned int _recordCount;
};


NdefMessage::NdefMessage(void)
{
    _recordCount = 0;
}

NdefMessage::NdefMessage(const byte * data, const int numBytes)
{
    #ifdef NDEF_DEBUG
    Serial.print(F("Decoding "));Serial.print(numBytes);Serial.println(F(" bytes"));
    PrintHexChar(data, numBytes);
    //DumpHex(data, numBytes, 16);
    #endif

    _recordCount = 0;

    int index = 0;

    while (index <= numBytes)
    {

        // decode tnf - first byte is tnf with bit flags
        // see the NFDEF spec for more info
        byte tnf_byte = data[index];
        // bool mb = tnf_byte & 0x80;
        bool me = tnf_byte & 0x40;
        // bool cf = tnf_byte & 0x20;
        bool sr = tnf_byte & 0x10;
        bool il = tnf_byte & 0x8;
        byte tnf = (tnf_byte & 0x7);

        NdefRecord record = NdefRecord();
        record.setTnf(tnf);

        index++;
        int typeLength = data[index];

        uint32_t payloadLength = 0;
        if (sr)
        {
            index++;
            payloadLength = data[index];
        }
        else
        {
            payloadLength =
                  (static_cast<uint32_t>(data[index])   << 24)
                | (static_cast<uint32_t>(data[index+1]) << 16)
                | (static_cast<uint32_t>(data[index+2]) << 8)
                |  static_cast<uint32_t>(data[index+3]);
            index += 4;
        }

        int idLength = 0;
        if (il)
        {
            index++;
            idLength = data[index];
        }

        index++;
        record.setType(&data[index], typeLength);
        index += typeLength;

        if (il)
        {
            record.setId(&data[index], idLength);
            index += idLength;
        }

        record.setPayload(&data[index], payloadLength);
        index += payloadLength;

        addRecord(record);

        if (me) break; // last message
    }

}

NdefMessage::NdefMessage(const NdefMessage& rhs)
{

    _recordCount = rhs._recordCount;
    for (unsigned int i = 0; i < _recordCount; i++)
    {
        _records[i] = rhs._records[i];
    }

}

NdefMessage::~NdefMessage()
{
}

NdefMessage& NdefMessage::operator=(const NdefMessage& rhs)
{

    if (this != &rhs)
    {

        // delete existing records
        for (unsigned int i = 0; i < _recordCount; i++)
        {
            // TODO Dave: is this the right way to delete existing records?
            _records[i] = NdefRecord();
        }

        _recordCount = rhs._recordCount;
        for (unsigned int i = 0; i < _recordCount; i++)
        {
            _records[i] = rhs._records[i];
        }
    }
    return *this;
}

unsigned int NdefMessage::getRecordCount()
{
    return _recordCount;
}

int NdefMessage::getEncodedSize()
{
    int size = 0;
    for (unsigned int i = 0; i < _recordCount; i++)
    {
        size += _records[i].getEncodedSize();
    }
    return size;
}

// TODO change this to return uint8_t*
void NdefMessage::encode(uint8_t* data)
{
    // assert sizeof(data) >= getEncodedSize()
    uint8_t* data_ptr = &data[0];

    for (unsigned int i = 0; i < _recordCount; i++)
    {
        _records[i].encode(data_ptr, i == 0, (i + 1) == _recordCount);
        // TODO can NdefRecord.encode return the record size?
        data_ptr += _records[i].getEncodedSize();
    }

}

boolean NdefMessage::addRecord(NdefRecord& record)
{

    if (_recordCount < MAX_NDEF_RECORDS)
    {
        _records[_recordCount] = record;
        _recordCount++;
        return true;
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.println(F("WARNING: Too many records. Increase MAX_NDEF_RECORDS."));
#endif
        return false;
    }
}

void NdefMessage::addMimeMediaRecord(String mimeType, String payload)
{

    byte payloadBytes[payload.length() + 1];
    payload.getBytes(payloadBytes, sizeof(payloadBytes));

    addMimeMediaRecord(mimeType, payloadBytes, payload.length());
}

void NdefMessage::addMimeMediaRecord(String mimeType, uint8_t* payload, int payloadLength)
{
    NdefRecord r = NdefRecord();
    r.setTnf(TNF_MIME_MEDIA);

    byte type[mimeType.length() + 1];
    mimeType.getBytes(type, sizeof(type));
    r.setType(type, mimeType.length());

    r.setPayload(payload, payloadLength);

    addRecord(r);
}

void NdefMessage::addTextRecord(String text)
{
    addTextRecord(text, "en");
}

void NdefMessage::addTextRecord(String text, String encoding)
{
    NdefRecord r = NdefRecord();
    r.setTnf(TNF_WELL_KNOWN);

    uint8_t RTD_TEXT[1] = { 0x54 }; // TODO this should be a constant or preprocessor
    r.setType(RTD_TEXT, sizeof(RTD_TEXT));

    // X is a placeholder for encoding length
    // TODO is it more efficient to build w/o string concatenation?
    String payloadString = "X" + encoding + text;

    byte payload[payloadString.length() + 1];
    payloadString.getBytes(payload, sizeof(payload));

    // replace X with the real encoding length
    payload[0] = encoding.length();

    r.setPayload(payload, payloadString.length());

    addRecord(r);
}

void NdefMessage::addUriRecord(String uri)
{
    NdefRecord* r = new NdefRecord();
    r->setTnf(TNF_WELL_KNOWN);

    uint8_t RTD_URI[1] = { 0x55 }; // TODO this should be a constant or preprocessor
    r->setType(RTD_URI, sizeof(RTD_URI));

    // X is a placeholder for identifier code
    String payloadString = "X" + uri;

    byte payload[payloadString.length() + 1];
    payloadString.getBytes(payload, sizeof(payload));

    // add identifier code 0x0, meaning no prefix substitution
    payload[0] = 0x0;

    r->setPayload(payload, payloadString.length());

    addRecord(*r);
    delete(r);
}

void NdefMessage::addEmptyRecord()
{
    NdefRecord* r = new NdefRecord();
    r->setTnf(TNF_EMPTY);
    addRecord(*r);
    delete(r);
}

NdefRecord NdefMessage::getRecord(int index)
{
    if (index > -1 && index < static_cast<int>(_recordCount))
    {
        return _records[index];
    }
    else
    {
        return NdefRecord(); // would rather return NULL
    }
}

NdefRecord NdefMessage::operator[](int index)
{
    return getRecord(index);
}

#ifdef NDEF_USE_SERIAL
void NdefMessage::print()
{
    Serial.print(F("\nNDEF Message "));Serial.print(_recordCount);Serial.print(F(" record"));
    _recordCount == 1 ? Serial.print(", ") : Serial.print("s, ");
    Serial.print(getEncodedSize());Serial.println(F(" bytes"));

    for (unsigned int i = 0; i < _recordCount; i++)
    {
         _records[i].print();
    }
}
#endif
