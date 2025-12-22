
rule Trojan_Win64_ShellcodeLoader_NOV_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.NOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8b 4c 24 70 48 8b c1 48 8b 4c 24 78 48 f7 f1 48 8b c2 48 8d 0d 88 ed 00 00 0f be 04 01 48 8b 4c 24 30 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 28 48 8b 54 24 30 88 04 0a e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}