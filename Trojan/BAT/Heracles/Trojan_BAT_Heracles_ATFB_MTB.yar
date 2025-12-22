
rule Trojan_BAT_Heracles_ATFB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ATFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 0c 02 28 ?? 00 00 0a 0d 00 09 73 ?? 00 00 0a 13 04 00 11 04 08 16 73 ?? 00 00 0a 13 05 00 11 05 28 ?? 00 00 0a 73 ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 0a de 36 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}