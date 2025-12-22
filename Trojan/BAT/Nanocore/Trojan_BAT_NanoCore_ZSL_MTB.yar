
rule Trojan_BAT_NanoCore_ZSL_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.ZSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 59 13 0f 1f 10 13 10 1e 13 11 16 13 12 25 11 10 1f 1f 5f 63 20 ff 00 00 00 5f d2 13 13 25 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}