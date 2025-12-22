
rule Trojan_BAT_Zusy_AJ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 06 11 04 11 06 16 7e 14 00 00 04 1c 94 fe 1c 0d 00 00 01 59 7e 14 00 00 04 1d 94 59 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}