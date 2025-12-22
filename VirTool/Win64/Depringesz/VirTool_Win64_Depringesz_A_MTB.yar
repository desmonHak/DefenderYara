
rule VirTool_Win64_Depringesz_A_MTB{
	meta:
		description = "VirTool:Win64/Depringesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 0f b6 ce c0 e9 04 41 2a c7 40 c0 e6 04 41 83 c5 03 40 c0 e5 02 40 0a e9 88 44 24 7b 40 0f b6 cf 42 88 2c 22 c0 e9 02 40 0a ce 40 c0 e7 06 40 0a f8 } //1
		$a_03_1 = {4c 8b 74 24 28 48 8b 6c 24 50 4c 8b bc 24 88 00 00 00 45 85 ed [0-14] 8b 4c 24 70 49 8b d4 4d 63 c5 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}