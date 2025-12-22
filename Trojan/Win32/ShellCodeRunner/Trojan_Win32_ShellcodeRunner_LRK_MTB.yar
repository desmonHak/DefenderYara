
rule Trojan_Win32_ShellcodeRunner_LRK_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.LRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 19 88 18 8b 5d fc 88 11 0f b6 00 8b 4d 08 0f b6 d2 03 c2 25 ff 00 00 80 79 ?? 48 0d ?? ff ff ff 40 8a 84 05 ?? fe ff ff 30 04 19 43 89 5d fc 3b 5d 0c 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}