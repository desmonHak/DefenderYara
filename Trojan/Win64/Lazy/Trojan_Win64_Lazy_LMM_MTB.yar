
rule Trojan_Win64_Lazy_LMM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 95 94 ec ff ff bf ca 00 00 00 2b fa 0f af f8 be a1 02 00 00 0f af f9 2b f2 0f af f0 6a 20 0f af f1 58 2b c2 83 c2 02 } //20
		$a_81_1 = {4d 4e 53 5c 48 65 66 6e 65 } //10 MNS\Hefne
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10) >=30
 
}