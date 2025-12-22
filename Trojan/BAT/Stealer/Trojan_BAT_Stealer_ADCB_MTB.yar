
rule Trojan_BAT_Stealer_ADCB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ADCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 26 0b 07 03 6f ?? 00 00 0a 07 04 6f ?? 00 00 0a 07 1f 0c 28 ?? 00 00 06 6f ?? 00 00 0a 07 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 1f 14 28 ?? 00 00 06 73 ?? 00 00 0a 0d 09 06 1f 18 28 ?? 00 00 06 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 de 45 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}