
rule Trojan_BAT_Stealer_ADDB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ADDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 00 11 07 17 58 13 07 } //5
		$a_01_1 = {07 11 06 1f 1f 5a 06 1d 5f 58 61 0b 16 13 0a } //2
		$a_01_2 = {06 11 0a 11 06 58 07 19 5f 58 61 0a 02 11 06 11 0a } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}