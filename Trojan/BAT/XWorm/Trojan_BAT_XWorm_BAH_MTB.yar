
rule Trojan_BAT_XWorm_BAH_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 0b 00 00 0a 0c 08 07 16 73 0c 00 00 0a 0d 73 0d 00 00 0a 13 04 09 11 04 ?? ?? 00 00 0a 11 04 ?? ?? 00 00 0a 13 05 de 34 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}