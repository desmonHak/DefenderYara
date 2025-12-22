
rule Trojan_BAT_Zilla_ZEL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0d 00 00 06 0a 06 6f ?? 00 00 06 00 73 ?? 01 00 06 06 7b ?? 00 00 04 28 ?? 01 00 06 0b 07 8e 16 fe 03 0c 08 39 16 00 00 00 00 73 ?? 00 00 06 25 07 7d ?? 00 00 04 0d 09 28 ?? 00 00 06 00 00 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}