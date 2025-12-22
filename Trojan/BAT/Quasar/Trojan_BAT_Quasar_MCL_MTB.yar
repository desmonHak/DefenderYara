
rule Trojan_BAT_Quasar_MCL_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 08 11 06 91 11 04 11 06 11 04 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}