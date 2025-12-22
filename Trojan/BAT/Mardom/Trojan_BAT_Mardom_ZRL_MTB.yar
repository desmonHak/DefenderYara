
rule Trojan_BAT_Mardom_ZRL_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ZRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 13 05 08 09 11 05 9c 09 17 58 0d 09 06 6f ?? 00 00 0a 32 db } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}