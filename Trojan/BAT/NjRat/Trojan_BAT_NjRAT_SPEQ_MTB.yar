
rule Trojan_BAT_NjRAT_SPEQ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.SPEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 ?? 00 00 0a 0c 08 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 14 13 04 11 04 13 05 09 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 14 6f ?? 00 00 0a 13 06 2a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}