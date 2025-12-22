
rule Trojan_Win64_Zusy_KAG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c2 89 84 95 64 01 00 00 48 ff c2 49 3b d0 } //20
		$a_01_1 = {77 63 74 45 45 35 44 2e 74 6d 70 } //10 wctEE5D.tmp
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}