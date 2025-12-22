
rule Backdoor_Linux_Mirai_LB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 31 d2 48 f7 f5 41 0f b6 04 14 30 04 19 48 ff c1 48 39 ce 75 e8 } //1
		$a_01_1 = {89 ca 89 f8 41 83 e8 04 c1 e2 0b c1 e8 13 31 ca 31 f8 89 d6 31 c2 c1 ee 08 31 d6 41 89 31 49 83 c1 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}