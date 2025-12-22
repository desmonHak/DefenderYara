
rule Trojan_BAT_Barys_AXBB_MTB{
	meta:
		description = "Trojan:BAT/Barys.AXBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 7e 01 00 00 04 7e 02 00 00 04 6f ?? 00 00 0a 0b 7e ?? 00 00 04 6f ?? 00 00 0a 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 09 13 04 2b 00 11 04 2a } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}