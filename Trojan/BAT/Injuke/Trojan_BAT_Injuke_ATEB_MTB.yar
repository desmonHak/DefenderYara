
rule Trojan_BAT_Injuke_ATEB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ATEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 91 13 06 06 7b ?? 00 00 04 07 11 05 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 06 61 d2 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 08 28 ?? 00 00 2b fe 04 13 07 11 07 2d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}