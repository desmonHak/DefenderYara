
rule Trojan_BAT_Stealer_AODB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AODB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 a6 11 a6 73 ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 a6 18 6f ?? 00 00 0a 11 a6 17 6f ?? 00 00 0a 11 a6 6f ?? 00 00 0a 02 16 02 8e b7 6f ?? 00 00 0a 13 05 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}