
rule Trojan_Win64_Rugmi_MZZ_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 eb d1 fa 8b c2 c1 e8 1f 03 d0 8d 14 52 c1 e2 02 41 8b c3 2b c2 48 63 d0 48 8d 05 7a 94 06 00 8a 04 02 d2 e0 41 30 04 28 41 ff c3 49 ff c0 4c 3b c3 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}