
rule Trojan_Win64_SnakeKeyLogger_GX_MTB{
	meta:
		description = "Trojan:Win64/SnakeKeyLogger.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 54 05 00 31 c2 83 f2 24 41 88 54 05 00 48 83 c0 01 39 c1 7f e8 } //2
		$a_81_1 = {42 4e 44 5f 25 30 38 58 2e 74 6d 70 } //1 BND_%08X.tmp
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}