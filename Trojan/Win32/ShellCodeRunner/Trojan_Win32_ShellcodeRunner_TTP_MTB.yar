
rule Trojan_Win32_ShellcodeRunner_TTP_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.TTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0f 8b 16 83 e8 15 88 04 0a 8b 06 31 d2 01 c8 89 45 ?? 89 c8 83 c1 01 f7 73 04 8b 03 0f b6 04 10 8b 55 e4 30 02 39 4d 10 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}