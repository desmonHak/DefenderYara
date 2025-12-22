
rule Trojan_BAT_XWorm_AEIB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AEIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 0a } //6
		$a_03_1 = {02 8e 69 16 30 08 16 8d ?? 00 00 01 2b 18 02 16 9a 17 8d ?? 00 00 01 13 } //2
		$a_03_2 = {0a 0b 06 16 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a de 0a 08 2c 06 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 0d de 14 } //2
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}