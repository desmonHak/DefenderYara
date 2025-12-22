
rule Trojan_Win32_BrightEgg_B_dha{
	meta:
		description = "Trojan:Win32/BrightEgg.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 ff 15 90 09 03 00 c7 45 } //5
		$a_02_1 = {6a 00 57 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 90 09 0b 00 68 ?? (39|90 03 01 01 3a 3b) 00 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*1) >=6
 
}