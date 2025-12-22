
rule Trojan_Win64_ShellcodeRunner_CH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 42 0f b6 0c 10 41 32 08 c0 c9 ?? 41 88 08 ff c2 83 e2 ?? 4d 8d 40 ?? 49 83 e9 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}