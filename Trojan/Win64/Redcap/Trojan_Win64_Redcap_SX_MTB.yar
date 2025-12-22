
rule Trojan_Win64_Redcap_SX_MTB{
	meta:
		description = "Trojan:Win64/Redcap.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 d7 48 f7 eb 48 c1 fa ?? 49 89 d8 48 c1 fb ?? 48 29 da 48 8d 1c 52 48 8d 1c 9a 49 29 d8 0f 57 c9 f2 49 0f 2a c8 } //6
		$a_03_1 = {48 89 d3 48 f7 ea 48 d1 fa 48 8b 84 24 ?? ?? ?? ?? 48 29 c2 48 8d 04 52 48 8d 04 42 48 29 c3 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}