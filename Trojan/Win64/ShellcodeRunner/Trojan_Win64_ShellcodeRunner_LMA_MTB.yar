
rule Trojan_Win64_ShellcodeRunner_LMA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8b c7 49 8b d6 [0-06] 00 49 83 f8 ?? 48 8d 52 01 49 8b cf 49 0f 45 c8 41 ff c1 0f b6 84 0d 18 01 00 00 4c 8d 41 01 30 42 ff 49 63 c1 48 3b c7 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}