
rule Trojan_BAT_Mardom_AHFB_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AHFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 28 ?? 00 00 0a 13 05 07 28 ?? 00 00 0a 13 06 11 04 11 05 11 06 6f ?? 00 00 0a 13 07 03 73 ?? 00 00 0a 13 08 11 08 11 07 16 73 ?? 00 00 0a 13 09 73 ?? 00 00 0a 13 0a 11 09 11 0a 6f ?? 00 00 0a 11 0a 6f ?? 00 00 0a 0c 1f 64 0d dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}