
rule Trojan_BAT_Zilla_ZBL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 06 fe 01 2c 07 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 28 ?? 00 00 06 33 14 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}