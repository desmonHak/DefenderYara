
rule Trojan_Win64_Radthief_AHD_MTB{
	meta:
		description = "Trojan:Win64/Radthief.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 d1 48 f7 eb 48 8d 34 13 48 c1 fe ?? 48 8d 34 b6 49 89 d8 48 29 f3 0f 57 c0 f2 48 0f 2a c3 } //20
		$a_03_1 = {4c 89 c9 49 d3 e0 4c 8d 5f 01 48 83 f9 ?? 4d 19 c9 4d 21 c8 41 b9 ?? ?? ?? ?? 4d 09 c8 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}