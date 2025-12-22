
rule Trojan_Win64_Radthief_SXC_MTB{
	meta:
		description = "Trojan:Win64/Radthief.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 19 48 c1 e3 ?? 8b 71 04 48 09 de 8b 59 20 48 c1 e3 ?? 8b 79 24 48 09 df 48 31 f7 } //10
		$a_03_1 = {48 c7 84 24 a8 01 00 00 0a ?? ?? ?? 48 c7 84 24 b0 01 00 00 14 ?? ?? ?? 48 c7 84 24 b8 01 00 00 1e ?? ?? ?? 48 c7 84 24 c0 01 00 00 28 ?? ?? ?? 48 c7 84 24 c8 01 00 00 32 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}