
rule Trojan_BAT_XWorm_BAD_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 04 08 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? d6 13 04 08 17 d6 0c 08 11 06 31 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}