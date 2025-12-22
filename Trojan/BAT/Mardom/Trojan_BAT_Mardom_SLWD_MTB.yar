
rule Trojan_BAT_Mardom_SLWD_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SLWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 39 30 00 00 00 16 3a 2a 00 00 00 72 ?? ?? 00 70 28 69 00 00 06 72 ?? ?? 00 70 28 69 00 00 06 d0 ?? 00 00 01 28 c2 00 00 0a 06 6f ?? 01 00 0a 28 51 00 00 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}