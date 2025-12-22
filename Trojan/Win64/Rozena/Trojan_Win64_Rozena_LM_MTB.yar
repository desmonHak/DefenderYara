
rule Trojan_Win64_Rozena_LM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be d2 69 d2 2d 15 00 00 4c 63 c2 4d 69 c0 31 0c c3 30 49 c1 f8 22 c1 fa 1f 41 29 d0 41 0f af c1 44 01 c0 48 83 c1 01 } //20
		$a_01_1 = {41 56 41 55 41 54 55 57 56 53 48 83 ec 28 48 89 ce 41 89 d4 48 85 c9 0f 94 c0 85 d2 0f 94 c2 08 d0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}