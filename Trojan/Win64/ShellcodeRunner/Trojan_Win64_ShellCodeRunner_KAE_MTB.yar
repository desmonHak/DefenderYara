
rule Trojan_Win64_ShellCodeRunner_KAE_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 18 8b 00 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 48 0f be c0 48 01 45 f8 48 8b 45 18 8b 00 8d 50 01 48 8b 45 18 89 10 } //20
		$a_01_1 = {48 8b 45 18 8b 00 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 84 c0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}