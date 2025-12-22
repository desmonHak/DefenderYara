
rule Trojan_Win64_Stealz_CH_MTB{
	meta:
		description = "Trojan:Win64/Stealz.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 54 45 41 4c 45 52 20 41 43 54 49 56 41 54 45 44 } //2 STEALER ACTIVATED
		$a_01_1 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //2 Chrome\User Data\Default\Login Data
		$a_01_2 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //2 api.telegram.org/bot
		$a_01_3 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //2 SELECT origin_url, username_value, password_value FROM logins
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}