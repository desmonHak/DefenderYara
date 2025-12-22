
rule Trojan_Win32_BrightEgg_A_dha{
	meta:
		description = "Trojan:Win32/BrightEgg.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 45 ?? 83 7d ?? 04 7d 1e 8b 45 08 03 45 ?? 0f b6 08 8b 55 0c 03 55 ?? 0f b6 02 33 c8 8b 55 10 03 55 ?? 88 0a eb d3 90 09 03 00 8b 45 } //1
		$a_00_1 = {8b f4 68 98 3a 00 00 ff 15 } //1
		$a_02_2 = {8b f4 6a 40 68 00 10 00 00 68 ?? 1c 00 00 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 45 ?? 68 ?? 1c 00 00 8b 45 ?? 50 8b 4d ?? 51 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}