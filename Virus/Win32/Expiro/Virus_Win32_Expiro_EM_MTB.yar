
rule Virus_Win32_Expiro_EM_MTB{
	meta:
		description = "Virus:Win32/Expiro.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 3d 84 d0 44 00 01 75 05 e8 68 8c 0d 00 } //5
		$a_01_1 = {8b f0 85 f6 75 0d 6a 12 e8 41 7e 0c 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}
rule Virus_Win32_Expiro_EM_MTB_2{
	meta:
		description = "Virus:Win32/Expiro.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 51 52 53 55 56 57 e8 00 00 00 00 } //2
		$a_01_1 = {81 c6 00 04 00 00 81 c0 00 04 00 00 81 fe 00 c0 08 00 0f 85 } //3
		$a_01_2 = {81 c6 00 04 00 00 81 c1 00 04 00 00 81 fe 00 c0 08 00 0f 85 } //3
		$a_01_3 = {81 c7 00 04 00 00 81 c2 00 04 00 00 81 ff 00 c0 08 00 0f 85 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}