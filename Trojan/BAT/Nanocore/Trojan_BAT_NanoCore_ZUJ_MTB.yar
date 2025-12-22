
rule Trojan_BAT_NanoCore_ZUJ_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.ZUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 05 11 06 6f ?? 00 00 0a 13 0a 09 11 04 6f ?? 00 00 0a 59 13 0b 11 04 17 8d ?? 00 00 01 25 16 12 0a 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 0b 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}