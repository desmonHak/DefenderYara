
rule Trojan_BAT_XWorm_MCN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 02 11 06 91 11 05 61 d2 9c 11 06 17 58 13 06 11 06 02 8e 69 32 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}