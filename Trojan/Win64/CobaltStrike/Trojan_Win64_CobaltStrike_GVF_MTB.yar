
rule Trojan_Win64_CobaltStrike_GVF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 0f b6 01 41 88 04 32 44 88 01 41 0f b6 04 32 4c 03 c0 41 0f b6 c0 0f b6 8c 04 10 03 00 00 41 30 09 49 ff c1 49 83 ee 01 75 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}