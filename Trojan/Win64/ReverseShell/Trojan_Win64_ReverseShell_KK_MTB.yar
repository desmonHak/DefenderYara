
rule Trojan_Win64_ReverseShell_KK_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 ac 24 88 00 00 00 48 8d ac 24 88 00 00 00 48 8b ?? ?? 1b 29 00 48 8b ?? ?? 1b 29 00 48 85 d2 } //20
		$a_01_1 = {48 89 5c 24 50 48 89 44 24 38 48 8b 48 18 48 89 d8 ff d1 48 85 db 0f 95 c1 48 8b 44 24 38 48 8b 5c 24 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}