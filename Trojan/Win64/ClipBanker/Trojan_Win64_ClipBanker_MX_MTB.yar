
rule Trojan_Win64_ClipBanker_MX_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0 48 8b 5c 24 30 48 83 c4 20 } //1
		$a_01_1 = {41 75 64 69 6f 48 65 6c 70 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 75 64 69 6f 48 65 6c 70 65 72 2e 70 64 62 } //1 AudioHelper\x64\Release\AudioHelper.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}