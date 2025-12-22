
rule Trojan_BAT_Heracles_AVEB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AVEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 15 2c 07 05 28 ?? 00 00 0a 0c 06 07 08 6f ?? 00 00 0a 0d 03 73 ?? 00 00 0a 13 04 11 04 09 16 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 2b 0f 2b 11 2b 13 11 06 6f ?? 00 00 0a 13 07 de 50 11 05 2b ed 11 06 2b eb 6f ?? 00 00 0a 2b e6 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}