
rule Trojan_Win64_ZooFang_C_dha{
	meta:
		description = "Trojan:Win64/ZooFang.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {07 0f b6 c8 48 8b c3 48 83 7b 18 08 72 03 48 8b 03 90 02 15 32 07 0f b6 c8 48 8b c3 48 83 7b 18 08 72 03 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}