
rule Trojan_BAT_Remcos_AHJB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 06 11 05 17 73 ?? 00 00 0a 13 06 00 03 11 06 6f ?? 00 00 0a 1d 2c 01 00 11 06 6f ?? 00 00 0a 00 06 16 6a 6f ?? 00 00 0a 16 2d e0 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}