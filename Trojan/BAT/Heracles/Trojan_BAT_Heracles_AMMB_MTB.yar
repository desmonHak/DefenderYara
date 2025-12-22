
rule Trojan_BAT_Heracles_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 2b 01 26 01 11 0f 28 ?? 00 00 06 11 0d 09 06 28 ?? 00 00 06 16 28 ?? 00 00 06 13 05 } //2
		$a_01_1 = {11 05 1b 5d 13 04 11 05 1b 5b 0c 16 0a 1f 09 13 06 2b a0 } //1
		$a_01_2 = {b4 e8 3d 35 06 6b de ca c2 5f 47 37 e6 44 02 a5 e9 24 4e c8 81 8c 4b 04 9e 7d 15 dc 63 c6 ef 38 84 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=5
 
}
rule Trojan_BAT_Heracles_AMMB_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 02 73 ?? ?? 00 0a 13 07 11 07 75 ?? 00 00 01 11 06 75 ?? 00 00 01 16 73 ?? ?? 00 0a 13 08 19 13 14 2b a8 02 8e 69 17 da 17 d6 8d ?? 00 00 01 13 09 11 08 74 ?? 00 00 01 11 09 75 ?? 00 00 1b 16 11 09 75 ?? 00 00 1b 8e 69 6f ?? ?? 00 0a 13 0a 18 13 14 38 ?? ff ff ff 11 0a 17 da 17 d6 8d ?? 00 00 01 13 0b 11 09 74 ?? 00 00 1b 11 0b 74 ?? 00 00 1b 11 0a 28 ?? ?? 00 0a 17 13 14 38 } //4
		$a_03_1 = {25 11 04 75 ?? 00 00 01 1f 20 6f ?? ?? 00 0a 6f ?? ?? 00 0a 25 11 04 74 ?? 00 00 01 1f 10 6f ?? ?? 00 0a 6f ?? ?? 00 0a 13 05 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}