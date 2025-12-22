
rule Trojan_Win32_Emotet_LMR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 5c 69 87 78 53 c7 44 24 24 dd be 53 57 c7 44 24 14 eb f8 19 1f c7 44 24 20 88 25 ee 3c c7 44 24 18 1e ec 9b 6c c7 44 24 40 82 8c 2a 18 c7 44 24 3c df 9b 13 7c c7 44 24 38 43 d7 32 13 c7 44 24 1c 43 0e 0a 03 } //20
		$a_03_1 = {46 3b f2 7c ?? 5e c3 69 05 ?? ?? ?? ?? fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}