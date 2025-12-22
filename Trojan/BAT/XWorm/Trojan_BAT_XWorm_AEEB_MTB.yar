
rule Trojan_BAT_XWorm_AEEB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AEEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 14 } //5
		$a_03_1 = {06 0a 06 03 7d ?? 00 00 04 02 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}