#include <SPI.h>




#define RST_PIN         20
#define DC_PIN          10
#define CS_PIN          7
#define BUSY_PIN        21
#define LED_PIN        8


// Display resolution
#define EPD_WIDTH   400
#define EPD_HEIGHT  300
#define EPD_ARRAY  EPD_WIDTH*EPD_HEIGHT/8


// Display resolution
#define WHITE       1
#define BLACK       0




//SPI write byte
void SPI_Write(unsigned char value)
{
  SPI.transfer(value);
}

//SPI write command
void EPD_W21_WriteCMD(unsigned char command)
{
  digitalWrite(CS_PIN, LOW);
  digitalWrite(DC_PIN, LOW); // D/C#   0:command  1:data
  SPI_Write(command);
  digitalWrite(CS_PIN, HIGH);
}
//SPI write data
void EPD_W21_WriteDATA(unsigned char datas)
{
  digitalWrite(CS_PIN, LOW);
  digitalWrite(DC_PIN, HIGH); // D/C#   0:command  1:data
  SPI_Write(datas);
  digitalWrite(CS_PIN, HIGH);
}




////////////////////////////////////E-paper demo//////////////////////////////////////////////////////////
//Busy function
void Epaper_READBUSY(void)
{
  while (1)
  { //=1 BUSY
    if (digitalRead(BUSY_PIN) == 0) break;
  }
}
//Full screen refresh initialization
void EPD_HW_Init(void)
{
  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10);//At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay

  Epaper_READBUSY();
  EPD_W21_WriteCMD(0x12);  //SWRESET
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x01); //Driver output control
  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x21); //  Display update control
  EPD_W21_WriteDATA(0x40);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x3C); //BorderWavefrom
  EPD_W21_WriteDATA(0x05);


  EPD_W21_WriteCMD(0x11); // set ram entry mode
  EPD_W21_WriteDATA(0x03);    // x increase, y increase : normal mode
  EPD_W21_WriteCMD(0x44);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteDATA((0 + EPD_WIDTH - 1) / 8);
  EPD_W21_WriteCMD(0x45);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) % 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) / 256);
  EPD_W21_WriteCMD(0x4e);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteCMD(0x4f);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);



  //  EPD_W21_WriteCMD(0x11); //data entry mode
  //  EPD_W21_WriteDATA(0x01);
  //
  //  EPD_W21_WriteCMD(0x44); //set Ram-X address start/end position
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(EPD_WIDTH / 8 - 1);
  //  EPD_W21_WriteCMD(0x45); //set Ram-Y address start/end position
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(0x00);
  //
  //  EPD_W21_WriteCMD(0x4E);   // set RAM x address count to 0;
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteCMD(0x4F);   // set RAM y address count to 0X199;
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);

  Epaper_READBUSY();

}
//Fast refresh 1 initialization
void EPD_HW_Init_Fast(void)
{
  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10);//At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay

  EPD_W21_WriteCMD(0x12);  //SWRESET
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x21);
  EPD_W21_WriteDATA(0x40);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x3C);
  EPD_W21_WriteDATA(0x05);

  //1.5s
  EPD_W21_WriteCMD(0x1A); // Write to temperature register
  EPD_W21_WriteDATA(0x6E);

  EPD_W21_WriteCMD(0x22); // Load temperature value
  EPD_W21_WriteDATA(0x91);
  EPD_W21_WriteCMD(0x20);
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x11); // set ram entry mode
  EPD_W21_WriteDATA(0x03);    // x increase, y increase : normal mode
  EPD_W21_WriteCMD(0x44);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteDATA((0 + EPD_WIDTH - 1) / 8);
  EPD_W21_WriteCMD(0x45);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) % 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) / 256);
  EPD_W21_WriteCMD(0x4e);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteCMD(0x4f);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);

  //
  //  EPD_W21_WriteCMD(0x11);  // Data entry mode
  //  EPD_W21_WriteDATA(0x01);
  //
  //  EPD_W21_WriteCMD(0x44); //set Ram-X address start/end position
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(EPD_WIDTH / 8 - 1);
  //
  //  EPD_W21_WriteCMD(0x45); //set Ram-Y address start/end position
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(0x00);
  //
  //  EPD_W21_WriteCMD(0x4E);   // set RAM x address count to 0;
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteCMD(0x4F);   // set RAM y address count to 0X199;
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  Epaper_READBUSY();

}


//////////////////////////////Display Update Function///////////////////////////////////////////////////////
//Full screen refresh update function
void EPD_Update(void)
{
  EPD_W21_WriteCMD(0x22); //Display Update Control
  EPD_W21_WriteDATA(0xF7);
  EPD_W21_WriteCMD(0x20); //Activate Display Update Sequence
  Epaper_READBUSY();

}
//Fast refresh 1 update function
void EPD_Update_Fast(void)
{
  EPD_W21_WriteCMD(0x22); //Display Update Control
  EPD_W21_WriteDATA(0xC7);
  EPD_W21_WriteCMD(0x20); //Activate Display Update Sequence
  Epaper_READBUSY();

}
//Partial refresh update function
void EPD_Part_Update(void)
{
  EPD_W21_WriteCMD(0x22); //Display Update Control
  EPD_W21_WriteDATA(0xFF);
  EPD_W21_WriteCMD(0x20); //Activate Display Update Sequence
  Epaper_READBUSY();
}
//////////////////////////////Display Data Transfer Function////////////////////////////////////////////
//Full screen refresh display function
void EPD_WhiteScreen_ALL(const unsigned char *datas)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_W21_WriteCMD(0x26);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_Update();
}
//Fast refresh display function
void EPD_WhiteScreen_ALL_Fast(const unsigned char *datas)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_W21_WriteCMD(0x26);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }

  EPD_Update_Fast();
}

//Clear screen display
void EPD_WhiteScreen_White(void)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(0xff);
  }
  EPD_W21_WriteCMD(0x26);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(0xff);
  }
  EPD_Update();
}
//Display all black
void EPD_WhiteScreen_Black(void)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(0x00);
  }
  EPD_W21_WriteCMD(0x26);   //write RAM for black(0)/white (1)
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(0x00);
  }
  EPD_Update();
}
//Partial refresh of background display, this function is necessary, please do not delete it!!!
void EPD_SetRAMValue_BaseMap( const unsigned char * datas)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //Write Black and White image to RAM
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_W21_WriteCMD(0x26);   //Write Black and White image to RAM
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_Update();
}

void EPD_SetRAMValue_BaseMap_NoUpdate( const unsigned char * datas)
{
  unsigned int i;
  EPD_W21_WriteCMD(0x24);   //Write Black and White image to RAM
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_W21_WriteCMD(0x26);   //Write Black and White image to RAM
  for (i = 0; i < EPD_ARRAY; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  //  EPD_Update();
}

//Partial refresh display
void EPD_Dis_Part(unsigned int x_start, unsigned int y_start, const unsigned char * datas, unsigned int PART_COLUMN, unsigned int PART_LINE)
{
  unsigned int i;
  unsigned int x_end, y_end;

  x_start = x_start / 8; //x address start
  x_end = x_start + PART_LINE / 8 - 1; //x address end
  y_start = y_start; //Y address start
  y_end = y_start + PART_COLUMN - 1; //Y address end

  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10);//At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay
  EPD_W21_WriteCMD(0x3C); //BorderWavefrom,
  EPD_W21_WriteDATA(0x80);

  EPD_W21_WriteCMD(0x21);
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x44);       // set RAM x address start/end
  EPD_W21_WriteDATA(x_start);  //x address start
  EPD_W21_WriteDATA(x_end);   //y address end
  EPD_W21_WriteCMD(0x45);    // set RAM y address start/end
  EPD_W21_WriteDATA(y_start % 256); //y address start2
  EPD_W21_WriteDATA(y_start / 256); //y address start1
  EPD_W21_WriteDATA(y_end % 256); //y address end2
  EPD_W21_WriteDATA(y_end / 256); //y address end1

  EPD_W21_WriteCMD(0x4E);        // set RAM x address count to 0;
  EPD_W21_WriteDATA(x_start);   //x start address
  EPD_W21_WriteCMD(0x4F);      // set RAM y address count to 0X127;
  EPD_W21_WriteDATA(y_start % 256); //y address start2
  EPD_W21_WriteDATA(y_start / 256); //y address start1


  EPD_W21_WriteCMD(0x24);   //Write Black and White image to RAM
  for (i = 0; i < PART_COLUMN * PART_LINE / 8; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_Part_Update();

}
//Full screen partial refresh display
void EPD_Dis_PartAll(const unsigned char * datas)
{
  unsigned int i;
  unsigned int PART_COLUMN, PART_LINE;
  PART_COLUMN = EPD_HEIGHT, PART_LINE = EPD_WIDTH;

  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10); //At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay
  EPD_W21_WriteCMD(0x3C); //BorderWavefrom,
  EPD_W21_WriteDATA(0x80);

  EPD_W21_WriteCMD(0x21);
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x24);   //Write Black and White image to RAM
  for (i = 0; i < PART_COLUMN * PART_LINE / 8; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
  EPD_Part_Update();

}
//Deep sleep function
void EPD_DeepSleep(void)
{
  EPD_W21_WriteCMD(0x10); //Enter deep sleep
  EPD_W21_WriteDATA(0x01);
  delay(10);
}

//Partial refresh write address and data
void EPD_Dis_Part_RAM(unsigned int x_start, unsigned int y_start, const unsigned char * datas, unsigned int PART_COLUMN, unsigned int PART_LINE)
{
  unsigned int i;
  unsigned int x_end, y_end;

  x_start = x_start / 8; //x address start
  x_end = x_start + PART_LINE / 8 - 1; //x address end

  y_start = y_start - 1; //Y address start
  y_end = y_start + PART_COLUMN - 1; //Y address end

  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10);//At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay

  EPD_W21_WriteCMD(0x21);
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x3C); //BorderWavefrom,
  EPD_W21_WriteDATA(0x80);

  EPD_W21_WriteCMD(0x44);       // set RAM x address start/end
  EPD_W21_WriteDATA(x_start);  //x address start
  EPD_W21_WriteDATA(x_end);   //y address end
  EPD_W21_WriteCMD(0x45);     // set RAM y address start/end
  EPD_W21_WriteDATA(y_start % 256); //y address start2
  EPD_W21_WriteDATA(y_start / 256); //y address start1
  EPD_W21_WriteDATA(y_end % 256); //y address end2
  EPD_W21_WriteDATA(y_end / 256); //y address end1

  EPD_W21_WriteCMD(0x4E);   // set RAM x address count to 0;
  EPD_W21_WriteDATA(x_start);   //x start address
  EPD_W21_WriteCMD(0x4F);   // set RAM y address count to 0X127;
  EPD_W21_WriteDATA(y_start % 256); //y address start2
  EPD_W21_WriteDATA(y_start / 256); //y address start1

  EPD_W21_WriteCMD(0x24);   //Write Black and White image to RAM
  for (i = 0; i < PART_COLUMN * PART_LINE / 8; i++)
  {
    EPD_W21_WriteDATA(datas[i]);
  }
}
//Clock display
void EPD_Dis_Part_Time(unsigned int x_startA, unsigned int y_startA, const unsigned char * datasA,
                       unsigned int x_startB, unsigned int y_startB, const unsigned char * datasB,
                       unsigned int x_startC, unsigned int y_startC, const unsigned char * datasC,
                       unsigned int x_startD, unsigned int y_startD, const unsigned char * datasD,
                       unsigned int x_startE, unsigned int y_startE, const unsigned char * datasE,
                       unsigned int PART_COLUMN, unsigned int PART_LINE
                      )
{
  EPD_Dis_Part_RAM(x_startA, y_startA, datasA, PART_COLUMN, PART_LINE);
  EPD_Dis_Part_RAM(x_startB, y_startB, datasB, PART_COLUMN, PART_LINE);
  EPD_Dis_Part_RAM(x_startC, y_startC, datasC, PART_COLUMN, PART_LINE);
  EPD_Dis_Part_RAM(x_startD, y_startD, datasD, PART_COLUMN, PART_LINE);
  EPD_Dis_Part_RAM(x_startE, y_startE, datasE, PART_COLUMN, PART_LINE);
  EPD_Part_Update();
}




////////////////////////////////Other newly added functions////////////////////////////////////////////
//Display rotation 180 degrees initialization
void EPD_HW_Init_180(void)
{
  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10); //At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay

  Epaper_READBUSY();
  EPD_W21_WriteCMD(0x12);  //SWRESET
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x21); //  Display update control
  EPD_W21_WriteDATA(0x40);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x3C); //BorderWavefrom
  EPD_W21_WriteDATA(0x05);


  EPD_W21_WriteCMD(0x11); //data entry mode
  EPD_W21_WriteDATA(0x02);

  EPD_W21_WriteCMD(0x44); //set Ram-X address start/end position
  EPD_W21_WriteDATA(EPD_WIDTH / 8 - 1);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x45); //set Ram-Y address start/end position
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);

  EPD_W21_WriteCMD(0x4E);   // set RAM x address count to 0;
  EPD_W21_WriteDATA(EPD_WIDTH / 8 - 1);
  EPD_W21_WriteCMD(0x4F);   // set RAM y address count to 0X199;
  EPD_W21_WriteDATA(0x00);
  EPD_W21_WriteDATA(0x00);
  Epaper_READBUSY();
}

//Fast refresh 2 initialization
void EPD_HW_Init_Fast2(void)
{
  digitalWrite(RST_PIN, LOW); // Module reset
  delay(10);//At least 10ms delay
  digitalWrite(RST_PIN, HIGH);
  delay(10); //At least 10ms delay

  EPD_W21_WriteCMD(0x12);  //SWRESET
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x21);
  EPD_W21_WriteDATA(0x40);
  EPD_W21_WriteDATA(0x00);

  EPD_W21_WriteCMD(0x3C);
  EPD_W21_WriteDATA(0x05);

  //1.0s
  EPD_W21_WriteCMD(0x1A); // Write to temperature register
  EPD_W21_WriteDATA(0x5A);

  EPD_W21_WriteCMD(0x22); // Load temperature value
  EPD_W21_WriteDATA(0x91);
  EPD_W21_WriteCMD(0x20);
  Epaper_READBUSY();

  EPD_W21_WriteCMD(0x11); // set ram entry mode
  EPD_W21_WriteDATA(0x03);    // x increase, y increase : normal mode
  EPD_W21_WriteCMD(0x44);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteDATA((0 + EPD_WIDTH - 1) / 8);
  EPD_W21_WriteCMD(0x45);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) % 256);
  EPD_W21_WriteDATA((0 + EPD_HEIGHT - 1) / 256);
  EPD_W21_WriteCMD(0x4e);
  EPD_W21_WriteDATA(0 / 8);
  EPD_W21_WriteCMD(0x4f);
  EPD_W21_WriteDATA(0 % 256);
  EPD_W21_WriteDATA(0 / 256);

  //
  //  EPD_W21_WriteCMD(0x11);  // Data entry mode
  //  EPD_W21_WriteDATA(0x01);
  //
  //  EPD_W21_WriteCMD(0x44); //set Ram-X address start/end position
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(EPD_WIDTH / 8 - 1);
  //  EPD_W21_WriteCMD(0x45); //set Ram-Y address start/end position
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteDATA(0x00);
  //
  //  EPD_W21_WriteCMD(0x4E);   // set RAM x address count to 0;
  //  EPD_W21_WriteDATA(0x00);
  //  EPD_W21_WriteCMD(0x4F);   // set RAM y address count to 0X199;
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) % 256);
  //  EPD_W21_WriteDATA((EPD_HEIGHT - 1) / 256);
  Epaper_READBUSY();
}

/***********************************************************
            end file
***********************************************************/