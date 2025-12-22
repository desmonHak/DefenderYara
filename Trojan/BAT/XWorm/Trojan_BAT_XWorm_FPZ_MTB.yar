
rule Trojan_BAT_XWorm_FPZ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.FPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 17 17 6f ?? 00 00 0a 28 ?? 00 00 0a 1c 62 02 18 17 6f ?? 00 00 0a 28 ?? 00 00 0a 19 62 60 02 19 17 6f ?? 00 00 0a 28 ?? 00 00 0a 60 d2 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}