
rule Trojan_BAT_Heracles_AYC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 72 61 00 00 70 28 09 00 00 0a 6f 0a 00 00 0a 00 06 72 bb 00 00 70 28 09 00 00 0a 6f 0b 00 00 0a 00 06 6f 0c 00 00 0a 0b 73 0d 00 00 0a 0c 08 07 17 73 0e 00 00 0a 0d 09 02 16 02 8e 69 6f 0f 00 00 0a 00 09 6f 10 00 00 0a 00 08 6f 11 00 00 0a 13 04 11 04 13 05 } //6
		$a_01_1 = {45 78 70 65 63 74 50 61 79 6c 6f 61 64 } //1 ExpectPayload
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}