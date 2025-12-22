
rule Trojan_BAT_XWorm_GAPA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GAPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 11 05 61 13 0f 07 11 0f 28 ?? 02 00 0a 28 ?? 02 00 0a 28 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}