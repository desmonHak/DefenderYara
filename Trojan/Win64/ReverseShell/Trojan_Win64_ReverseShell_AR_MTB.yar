
rule Trojan_Win64_ReverseShell_AR_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 50 48 89 45 48 48 8b 45 48 48 89 45 40 48 8d 05 ?? ?? ?? ?? 48 8d 55 d0 48 89 54 24 48 48 8d 55 f0 48 89 54 24 40 48 c7 44 24 38 00 00 00 00 } //10
		$a_03_1 = {48 8d ac 24 80 00 00 00 e8 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 89 85 ?? 02 00 00 c7 85 ?? 02 00 00 5c 11 00 00 } //5
		$a_01_2 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=16
 
}