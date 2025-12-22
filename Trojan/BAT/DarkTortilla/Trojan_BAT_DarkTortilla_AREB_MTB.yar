
rule Trojan_BAT_DarkTortilla_AREB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AREB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 07 11 07 28 ?? ?? 00 0a 03 28 ?? ?? 00 06 b4 6f ?? ?? 00 0a 00 00 11 06 6f ?? ?? 00 0a 13 08 11 08 2d cf } //5
		$a_01_1 = {02 03 61 0b 07 0a 2b 00 06 2a } //2 ̂ୡਇ+⨆
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}