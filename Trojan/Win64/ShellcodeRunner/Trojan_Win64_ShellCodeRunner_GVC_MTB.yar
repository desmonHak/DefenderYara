
rule Trojan_Win64_ShellCodeRunner_GVC_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 f8 48 8b 45 ?? 48 01 d0 0f b6 00 48 8b 4d f8 48 8b 55 ?? 48 01 ca 32 45 c7 88 02 [0-0f] 48 83 45 ?? 01 48 8b 45 ?? 48 3b 45 f0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}