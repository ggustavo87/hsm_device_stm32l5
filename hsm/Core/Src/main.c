/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "crypto_manager.h"
#include "hal_octospi_utility.h"
#include "mbedtls.h"

/* Private includes ----------------------------------------------------------*/

/* Private typedef -----------------------------------------------------------*/
/* Define enum for menu options */
typedef enum {
    DUMP_MEMORY = '1',
    ENABLE_OTFDEC = '2',
    LAUNCH_APPLI = '3',
    GENERATE_AES_KEY = '4',
    AES_ENCRYPT = '5',
    AES_DECRYPT = '6',
    GENERATE_ECDSA_KEYS = '7'
} MenuOption;


/* Private define ------------------------------------------------------------*/
#define KEY_SIZE 32 // 256-bit key size for AES-256

#define START_ADRESS_OCTOSPI1            0x90000000
#define START_ADRESS_OTFDEC1_REGION2     0x90000000
#define END_ADRESS_OTFDEC1_REGION2       0x90007FFF
#define DUMP_SIZE  8

/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/

OSPI_HandleTypeDef hospi1;

OTFDEC_HandleTypeDef hotfdec1;

PKA_HandleTypeDef hpka;

RNG_HandleTypeDef hrng;

RTC_HandleTypeDef hrtc;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
OTFDEC_RegionConfigTypeDef Config = {0};
uint32_t otfdec_key[4]={0xA9876543, 0x210FEDCB, 0xA9876543, 0x210FEDCB};

unsigned char session_key[KEY_SIZE]= {0};

unsigned char test_key[KEY_SIZE] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
};

/* Ciphered instructions */
uint8_t input;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_ICACHE_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_OCTOSPI1_Init(void);
static void MX_OTFDEC1_Init(void);
static void MX_RTC_Init(void);
static void MX_RNG_Init(void);
static void MX_PKA_Init(void);

/* Private user code ---------------------------------------------------------*/

void APP_PrintMainMenu(void);
void APP_DumpMemory(void);
void APP_ActivateOTFDEC(void);
void APP_LaunchAppli(void);

void mbedtls_error_handler(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    printf("Error: %s\n", error_buf);
}

void APP_DumpMemory(void) {

	uint32_t *ptr = (uint32_t *)START_ADRESS_OTFDEC1_REGION2;
    printf("\r\nMemory Dump\r\n");
	for (uint8_t i=0; i<DUMP_SIZE;i++)
	{
	  printf("0x%08.8X :  %08.8X %08.8X %08.8X %08.8X\r\n",ptr ,*ptr, *(ptr+1),*(ptr+2) ,*(ptr+3) );
	  ptr=ptr+4;
	}
}

void APP_ActivateOTFDEC(void) {
	  __HAL_OTFDEC_ENABLE_IT(&hotfdec1, OTFDEC_ALL_INT);

	  /* Set OTFDEC Mode */
	  if (HAL_OTFDEC_RegionSetMode(&hotfdec1, OTFDEC_REGION2, OTFDEC_REG_MODE_INSTRUCTION_OR_DATA_ACCESSES) != HAL_OK)
	  {
	    Error_Handler();
	  }

	  /* Set OTFDEC Key */
	  if (HAL_OTFDEC_RegionSetKey(&hotfdec1, OTFDEC_REGION2, otfdec_key) != HAL_OK)
	  {
	    Error_Handler();
	   }


	  /* Configure then activate OTFDEC decryption */
	  Config.Nonce[0]     = 0x11111111;
	  Config.Nonce[1]     = 0x55555555;
	  Config.StartAddress = START_ADRESS_OTFDEC1_REGION2;
	  Config.EndAddress   = END_ADRESS_OTFDEC1_REGION2;
	  Config.Version      = 0xA5A5;
	  if (HAL_OTFDEC_RegionConfig(&hotfdec1, OTFDEC_REGION2, &Config, OTFDEC_REG_CONFIGR_LOCK_ENABLE) != HAL_OK)
	  {
	    Error_Handler();
	  }

  	  printf("   !!! OTFDEC has been activated on region : 0x%08.8X 0x%08.8X\r\n\n",START_ADRESS_OTFDEC1_REGION2,END_ADRESS_OTFDEC1_REGION2);

}

void APP_LaunchAppli(void)
{
    typedef  void (*pFunction)(void);

    pFunction JumpToApplication;
    uint32_t JumpAddress;

    JumpAddress = *(__IO uint32_t*) (START_ADRESS_OTFDEC1_REGION2 + 4);
    if (( JumpAddress >= START_ADRESS_OTFDEC1_REGION2 ) && (JumpAddress < END_ADRESS_OTFDEC1_REGION2 ))
		{
			JumpToApplication = (pFunction) JumpAddress;
			JumpToApplication();
		}
    else
    {
  	  printf("   !!! Error no application at 0x%08.8X  !!!\r\n\n",START_ADRESS_OTFDEC1_REGION2);

    }
}

int __io_putchar(int ch)
{
  /* Place your implementation of fputc here */
  /* e.g. write a character to the USART1 and Loop until the end of transmission */
  HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 0xFFFF);

  return ch;
}

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();
  /* Configure the system clock */
  SystemClock_Config();

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_ICACHE_Init();
  MX_USART1_UART_Init();
  MX_OCTOSPI1_Init();
  MX_OTFDEC1_Init();
  MX_RTC_Init();
  MX_MBEDTLS_Init();
  MX_RNG_Init();
  MX_PKA_Init();
  OSPI_Config() ;
  OSPI_MemoryMap();

  /* End of MCU Configuration--------------------------------------------------*/

  int ret;
  unsigned char iv[16] = {0}; // IV for AES-CBC is 16
  unsigned char iv1[16] = {0};
  const char *plain_text = "This is a test text";
  unsigned char encrypted_text[256] = {0};
  unsigned char decrypted_text[256] = {0};
  size_t ciphertext_len =0;
  size_t plain_text_len = strlen(plain_text);

  crypto_manager_init();


  printf("\r\n***********************************************************\r\n");
  printf("\r\n*             ERNI Hardware Secure Module                 *\r\n");
  printf("\r\n***********************************************************\r\n");
  APP_PrintMainMenu();

  /* Infinite loop */
  while (1)
  {
	  __HAL_UART_FLUSH_DRREGISTER(&huart1);
	  if ( HAL_OK== HAL_UART_Receive(&huart1, (uint8_t *)&input, 1, 2000))
      {
		  switch (input) {
		  case DUMP_MEMORY:
			  APP_DumpMemory();
			  break;
		  case ENABLE_OTFDEC:
			  APP_ActivateOTFDEC();
			  break;
		  case LAUNCH_APPLI:
			  APP_LaunchAppli();
			  break;
		  case GENERATE_AES_KEY:
			  if (aes_generate_key(session_key, AES_KEY_SIZE)) {
				  printf("Failed to generate random key\n");
				  return 1;
			  }

			  printf("AES Key: ");
			  for (size_t i = 0; i < AES_KEY_SIZE; i++) {
				//Print in HEX
				printf("%02X", session_key[i]);
			  }
			  printf("\n");

			  break;
		  case AES_ENCRYPT:
			  uint8_t buffer[256] = ""; // Max lenght 256 bytes
			  size_t message_len = 0;

			  // Read the rest of the message
			  while (message_len < sizeof(buffer) - 1) // -1 for null termination
			  {
				  if (HAL_OK == HAL_UART_Receive(&huart1, &buffer[message_len], 1, 2000))
				  {
					  if (buffer[message_len] == '\n' || buffer[message_len] == '\r')
					  {
						  // End of message reached
						  break;
					  }
					  message_len++;
				  }
			  }

			  buffer[message_len] = '\0';

			  if (aes_encrypt(buffer, message_len, session_key, iv, encrypted_text, &ciphertext_len)) {
				  printf("Encryption failed\n");
				  return 1;
			  }

			  print_base64_encoded_message(encrypted_text, ciphertext_len);

			  /*if (aes_decrypt(encrypted_text, ciphertext_len, session_key, iv1, decrypted_text)) {
			      printf("Decryption failed\n");
			      return 1;
			  }
			  printf("Decripted message: %s\n", decrypted_text);*/
			  break;

		  case AES_DECRYPT:
		      // Decrypt the encrypted message
		      if (aes_decrypt(encrypted_text, ciphertext_len, session_key, iv1, decrypted_text)) {
		          printf("Decryption failed\n");
		          return 1;
		      }
		      printf("Decrypted Message: %s\n", decrypted_text);
		      break;

		  case GENERATE_ECDSA_KEYS:
		      break;
		  }
      }

  }
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE0) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_LSI|RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.LSIDiv = RCC_LSI_DIV1;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_11;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
  RCC_OscInitStruct.PLL.PLLM = 12;
  RCC_OscInitStruct.PLL.PLLN = 55;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV7;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief ICACHE Initialization Function
  * @param None
  * @retval None
  */
static void MX_ICACHE_Init(void)
{

  /* USER CODE BEGIN ICACHE_Init 0 */

  /* USER CODE END ICACHE_Init 0 */

  /* USER CODE BEGIN ICACHE_Init 1 */

  /* USER CODE END ICACHE_Init 1 */

  /** Enable instruction cache in 1-way (direct mapped cache)
  */
  if (HAL_ICACHE_ConfigAssociativityMode(ICACHE_1WAY) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_ICACHE_Enable() != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN ICACHE_Init 2 */

  /* USER CODE END ICACHE_Init 2 */

}

/**
  * @brief OCTOSPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_OCTOSPI1_Init(void)
{

  /* USER CODE BEGIN OCTOSPI1_Init 0 */

  /* USER CODE END OCTOSPI1_Init 0 */

  /* USER CODE BEGIN OCTOSPI1_Init 1 */

  /* USER CODE END OCTOSPI1_Init 1 */
  /* OCTOSPI1 parameter configuration*/
  hospi1.Instance = OCTOSPI1;
  hospi1.Init.FifoThreshold = 4;
  hospi1.Init.DualQuad = HAL_OSPI_DUALQUAD_DISABLE;
  hospi1.Init.MemoryType = HAL_OSPI_MEMTYPE_MACRONIX;
  hospi1.Init.DeviceSize = 26;
  hospi1.Init.ChipSelectHighTime = 2;
  hospi1.Init.FreeRunningClock = HAL_OSPI_FREERUNCLK_DISABLE;
  hospi1.Init.ClockMode = HAL_OSPI_CLOCK_MODE_0;
  hospi1.Init.WrapSize = HAL_OSPI_WRAP_NOT_SUPPORTED;
  hospi1.Init.ClockPrescaler = 2;
  hospi1.Init.SampleShifting = HAL_OSPI_SAMPLE_SHIFTING_NONE;
  hospi1.Init.DelayHoldQuarterCycle = HAL_OSPI_DHQC_ENABLE;
  hospi1.Init.ChipSelectBoundary = 0;
  hospi1.Init.DelayBlockBypass = HAL_OSPI_DELAY_BLOCK_USED;
  hospi1.Init.Refresh = 0;
  if (HAL_OSPI_Init(&hospi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN OCTOSPI1_Init 2 */

  /* USER CODE END OCTOSPI1_Init 2 */

}
/**
  * @brief OTFDEC1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_OTFDEC1_Init(void)
{

  /* USER CODE BEGIN OTFDEC1_Init 0 */

  /* USER CODE END OTFDEC1_Init 0 */

  /* USER CODE BEGIN OTFDEC1_Init 1 */

  /* USER CODE END OTFDEC1_Init 1 */
  hotfdec1.Instance = OTFDEC1;
  if (HAL_OTFDEC_Init(&hotfdec1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN OTFDEC1_Init 2 */

  /* USER CODE END OTFDEC1_Init 2 */

}

/**
  * @brief PKA Initialization Function
  * @param None
  * @retval None
  */
static void MX_PKA_Init(void)
{

  /* USER CODE BEGIN PKA_Init 0 */

  /* USER CODE END PKA_Init 0 */

  /* USER CODE BEGIN PKA_Init 1 */

  /* USER CODE END PKA_Init 1 */
  hpka.Instance = PKA;
  if (HAL_PKA_Init(&hpka) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN PKA_Init 2 */

  /* USER CODE END PKA_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief RTC Initialization Function
  * @param None
  * @retval None
  */
static void MX_RTC_Init(void)
{

  /* USER CODE BEGIN RTC_Init 0 */

  /* USER CODE END RTC_Init 0 */

  RTC_PrivilegeStateTypeDef privilegeState = {0};

  /* USER CODE BEGIN RTC_Init 1 */

  /* USER CODE END RTC_Init 1 */

  /** Initialize RTC Only
  */
  hrtc.Instance = RTC;
  hrtc.Init.HourFormat = RTC_HOURFORMAT_24;
  hrtc.Init.AsynchPrediv = 127;
  hrtc.Init.SynchPrediv = 255;
  hrtc.Init.OutPut = RTC_OUTPUT_DISABLE;
  hrtc.Init.OutPutRemap = RTC_OUTPUT_REMAP_NONE;
  hrtc.Init.OutPutPolarity = RTC_OUTPUT_POLARITY_HIGH;
  hrtc.Init.OutPutType = RTC_OUTPUT_TYPE_OPENDRAIN;
  hrtc.Init.OutPutPullUp = RTC_OUTPUT_PULLUP_NONE;
  if (HAL_RTC_Init(&hrtc) != HAL_OK)
  {
    Error_Handler();
  }
  privilegeState.rtcPrivilegeFull = RTC_PRIVILEGE_FULL_NO;
  privilegeState.backupRegisterPrivZone = RTC_PRIVILEGE_BKUP_ZONE_NONE;
  privilegeState.backupRegisterStartZone2 = RTC_BKP_DR0;
  privilegeState.backupRegisterStartZone3 = RTC_BKP_DR0;
  if (HAL_RTCEx_PrivilegeModeSet(&hrtc, &privilegeState) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RTC_Init 2 */

  /* USER CODE END RTC_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;

  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOG_CLK_ENABLE();
  HAL_PWREx_EnableVddIO2();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOG, LED_GREEN_Pin|BLE_RSTN_Pin|AUDIO_RESETN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_RED_GPIO_Port, LED_RED_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(UCPD_DBn_GPIO_Port, UCPD_DBn_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LCD_TE_GPIO_Port, LCD_TE_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LCD_PWR_ON_GPIO_Port, LCD_PWR_ON_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOF, LCD_RST_Pin|STMOD_SEL_12_Pin|STMOD_SEL_34_Pin|CTP_RST_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pins : PE5 PE3 PE4 PE2
                           PE6 */
  GPIO_InitStruct.Pin = GPIO_PIN_5|GPIO_PIN_3|GPIO_PIN_4|GPIO_PIN_2
                          |GPIO_PIN_6;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF13_SAI1;
  HAL_GPIO_Init(GPIOE, &GPIO_InitStruct);

  /*Configure GPIO pin : LCD_BL_PWM_Pin */
  GPIO_InitStruct.Pin = LCD_BL_PWM_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF14_TIM17;
  HAL_GPIO_Init(LCD_BL_PWM_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : PB6 PB7 */
  GPIO_InitStruct.Pin = GPIO_PIN_6|GPIO_PIN_7;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_OD;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF4_I2C1;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pins : LED_GREEN_Pin BLE_RSTN_Pin AUDIO_RESETN_Pin */
  GPIO_InitStruct.Pin = LED_GREEN_Pin|BLE_RSTN_Pin|AUDIO_RESETN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOG, &GPIO_InitStruct);

  /*Configure GPIO pins : PD5 PD4 PD1 PD0
                           PD7 PD14 PD15 PD9
                           PD8 PD10 */
  GPIO_InitStruct.Pin = GPIO_PIN_5|GPIO_PIN_4|GPIO_PIN_1|GPIO_PIN_0
                          |GPIO_PIN_7|GPIO_PIN_14|GPIO_PIN_15|GPIO_PIN_9
                          |GPIO_PIN_8|GPIO_PIN_10;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF12_FMC;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pin : PD2 */
  GPIO_InitStruct.Pin = GPIO_PIN_2;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF12_SDMMC1;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pins : PC11 PC12 PC10 PC9
                           PC8 */
  GPIO_InitStruct.Pin = GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_10|GPIO_PIN_9
                          |GPIO_PIN_8;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF12_SDMMC1;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  /*Configure GPIO pins : PA15 VBUS_SENSE_Pin */
  GPIO_InitStruct.Pin = GPIO_PIN_15|VBUS_SENSE_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pins : PA12 PA11 */
  GPIO_InitStruct.Pin = GPIO_PIN_12|GPIO_PIN_11;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF10_USB;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pin : USER_BUTTON_Pin */
  GPIO_InitStruct.Pin = USER_BUTTON_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(USER_BUTTON_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LED_RED_Pin */
  GPIO_InitStruct.Pin = LED_RED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LED_RED_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PF0 */
  GPIO_InitStruct.Pin = GPIO_PIN_0;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF12_FMC;
  HAL_GPIO_Init(GPIOF, &GPIO_InitStruct);

  /*Configure GPIO pins : GYRO_ACC_INT_Pin SDIO_DETECT_Pin CTP_INT_Pin */
  GPIO_InitStruct.Pin = GYRO_ACC_INT_Pin|SDIO_DETECT_Pin|CTP_INT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOF, &GPIO_InitStruct);

  /*Configure GPIO pin : UCPD_DBn_Pin */
  GPIO_InitStruct.Pin = UCPD_DBn_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(UCPD_DBn_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LCD_TE_Pin */
  GPIO_InitStruct.Pin = LCD_TE_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LCD_TE_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LCD_PWR_ON_Pin */
  GPIO_InitStruct.Pin = LCD_PWR_ON_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LCD_PWR_ON_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : BLE_INT_Pin */
  GPIO_InitStruct.Pin = BLE_INT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BLE_INT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PG7 */
  GPIO_InitStruct.Pin = GPIO_PIN_7;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF6_DFSDM1;
  HAL_GPIO_Init(GPIOG, &GPIO_InitStruct);

  /*Configure GPIO pins : PG4 PG2 PG3 BLE_CSN_Pin */
  GPIO_InitStruct.Pin = GPIO_PIN_4|GPIO_PIN_2|GPIO_PIN_3|BLE_CSN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI1;
  HAL_GPIO_Init(GPIOG, &GPIO_InitStruct);

  /*Configure GPIO pins : LCD_RST_Pin STMOD_SEL_12_Pin STMOD_SEL_34_Pin CTP_RST_Pin */
  GPIO_InitStruct.Pin = LCD_RST_Pin|STMOD_SEL_12_Pin|STMOD_SEL_34_Pin|CTP_RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOF, &GPIO_InitStruct);

  /*Configure GPIO pins : PE8 PE10 PE12 PE7
                           PE14 PE11 PE15 PE9
                           PE13 */
  GPIO_InitStruct.Pin = GPIO_PIN_8|GPIO_PIN_10|GPIO_PIN_12|GPIO_PIN_7
                          |GPIO_PIN_14|GPIO_PIN_11|GPIO_PIN_15|GPIO_PIN_9
                          |GPIO_PIN_13;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF12_FMC;
  HAL_GPIO_Init(GPIOE, &GPIO_InitStruct);

  /*Configure GPIO pins : PB10 PB11 */
  GPIO_InitStruct.Pin = GPIO_PIN_10|GPIO_PIN_11;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF8_LPUART1;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pin : UCPD_FLT_Pin */
  GPIO_InitStruct.Pin = UCPD_FLT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(UCPD_FLT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PB15 */
  GPIO_InitStruct.Pin = GPIO_PIN_15;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pin : PB12 */
  GPIO_InitStruct.Pin = GPIO_PIN_12;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF6_DFSDM1;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
void APP_PrintMainMenu(void)
{
	  printf("\r\n=================== HSM Commands ===========================\r\n\n");
	  printf("  Dump data from external Memory (0x%08.8X) ------------1\r\n\n",START_ADRESS_OTFDEC1_REGION2);
	  printf("  Enable OTFDEC ----------------------------------------- 2\r\n\n");
	  printf("  Launch binary at  0x%08.8X -------------------------- 3\r\n\n",START_ADRESS_OTFDEC1_REGION2);
	  printf("  Generate session key using AES-CBC--------------------- 4\r\n\n");
	  printf("  Encrypt message using session key --------------------- 5\r\n\n");
	  printf("  Decrypt message using session key --------------------- 6\r\n\n");
	  printf("  Generate ECDSA key pair -------------------------------- 7\r\n\n");
	  printf("  Selection :\r\n\n");
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/** statu
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

