
rule Trojan_Win64_VampireBot_AVB_MTB{
	meta:
		description = "Trojan:Win64/VampireBot.AVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 34 11 89 f7 40 c0 ee 04 40 0f b6 f6 4c 8d 05 4e c3 21 00 42 0f b6 34 06 48 83 fb 20 0f 83 3d ?? ?? ?? 40 88 34 18 48 8d 73 01 83 e7 0f 42 0f b6 3c 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}