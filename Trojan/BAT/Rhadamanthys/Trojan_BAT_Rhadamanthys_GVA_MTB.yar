
rule Trojan_BAT_Rhadamanthys_GVA_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0b 2b 1e 7e 39 00 00 04 11 0b 93 11 0a 33 0c 11 06 1f 3a 5a 11 0b 58 13 06 2b 0c 11 0b 17 58 13 0b 11 0b 1f 3a 32 dc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}