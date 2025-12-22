
rule Trojan_Win64_ShellCodeRunner_GDZ_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 7b f8 49 89 be ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 54 24 40 ff 15 ?? ?? ?? ?? 83 7c 24 40 00 74 ?? b9 ff ff ff ff ff 15 ?? ?? ?? ?? cc 48 8d 46 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}