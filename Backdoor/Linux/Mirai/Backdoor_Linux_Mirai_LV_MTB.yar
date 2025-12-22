
rule Backdoor_Linux_Mirai_LV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 83 ec 08 8b 54 24 10 8b 4c 24 14 87 d3 b8 21 00 00 00 cd 80 87 d3 89 c3 3d 00 f0 ff ff 76 0c e8 a1 05 00 00 f7 db 89 18 83 cb ff } //1
		$a_01_1 = {53 83 ec 08 8b 54 24 10 8b 4c 24 14 87 d3 b8 3f 00 00 00 cd 80 87 d3 89 c3 3d 00 f0 ff ff 76 0c e8 e0 04 00 00 f7 db 89 18 83 cb ff } //1
		$a_01_2 = {53 83 ec 08 8b 54 24 10 0f b7 4c 24 14 87 d3 b8 0f 00 00 00 cd 80 87 d3 89 c3 3d 00 f0 ff ff 76 0c e8 40 05 00 00 f7 db 89 18 83 cb ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}