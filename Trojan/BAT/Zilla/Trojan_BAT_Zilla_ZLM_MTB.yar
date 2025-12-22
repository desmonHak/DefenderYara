
rule Trojan_BAT_Zilla_ZLM_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 17 58 13 06 11 06 06 8e 69 32 c3 11 05 28 ?? 00 00 06 13 04 73 ?? 00 00 0a 13 09 11 09 08 6f ?? 00 00 0a 11 09 09 6f ?? 00 00 0a 11 09 6f ?? 00 00 0a 13 0a 11 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 04 11 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}