
rule Trojan_BAT_AsyncRAT_SLNH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SLNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 1c 00 00 04 a2 25 28 ?? 01 00 06 28 32 00 00 0a 28 25 00 00 06 28 ?? ?? ?? 06 28 33 00 00 0a 28 34 00 00 0a a2 25 28 ?? 01 00 06 7e 16 00 00 04 a2 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}