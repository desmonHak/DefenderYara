
rule Trojan_BAT_Mardom_SLEI_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SLEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 26 06 00 04 72 b7 01 00 70 6f 8d 01 00 0a 73 6b 09 00 06 25 6f 6c 09 00 06 16 6a 6f 08 01 00 0a 25 25 6f 6c 09 00 06 6f 05 01 00 0a 69 6f 6d 09 00 06 13 04 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}