
rule Trojan_Win32_ShellcodeRunner_AHE_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 ff d0 89 45 d8 8d 85 c0 fe ff ff 89 04 24 8b 45 dc ff d0 83 ec ?? 85 c0 74 } //30
		$a_03_1 = {8b 45 f4 8b 40 ?? 89 45 d4 8b 45 d4 83 c0 ?? 89 45 ec 8b 45 d4 83 c0 ?? 89 45 e8 83 7d f0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}