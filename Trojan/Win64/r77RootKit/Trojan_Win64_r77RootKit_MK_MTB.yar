
rule Trojan_Win64_r77RootKit_MK_MTB{
	meta:
		description = "Trojan:Win64/r77RootKit.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 3c 0f b7 c9 8b 44 30 78 2b 4c 30 10 8b 44 30 1c 8d 04 88 8b 04 30 03 c6 } //25
		$a_03_1 = {0f b7 c9 6b d1 ?? 0f b7 c6 48 3b c8 8b 4d f8 89 55 d8 } //10
	condition:
		((#a_01_0  & 1)*25+(#a_03_1  & 1)*10) >=35
 
}