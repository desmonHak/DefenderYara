
rule Trojan_BAT_DarkCloud_AMJB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AMJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 12 00 28 ?? 00 00 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 7b ?? 00 00 04 6f ?? 00 00 0a 59 73 ?? 00 00 0a 2a } //5
		$a_03_1 = {06 0a 06 03 7d ?? 00 00 04 16 19 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 2a } //2
		$a_01_2 = {0a 18 03 59 1e 5a 1f 1f 5f 63 20 ff 00 00 00 5f d2 2a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}