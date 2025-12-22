
rule Trojan_BAT_Convagent_ALIB_MTB{
	meta:
		description = "Trojan:BAT/Convagent.ALIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 06 7b ?? 00 00 04 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 04 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 2a } //5
		$a_03_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}