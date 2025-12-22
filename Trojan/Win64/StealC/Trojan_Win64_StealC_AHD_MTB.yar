
rule Trojan_Win64_StealC_AHD_MTB{
	meta:
		description = "Trojan:Win64/StealC.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 73 11 41 c1 e6 ?? 41 0b ee 44 0f b6 73 12 41 c1 e6 ?? 41 0b ee 44 0f b6 73 13 41 c1 e6 ?? 41 0b ee } //30
		$a_03_1 = {8b ce 40 0f b6 7c 0b ?? 49 8b cf e8 ?? ?? ?? ?? 33 c7 40 0f b6 f8 41 3b 76 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}