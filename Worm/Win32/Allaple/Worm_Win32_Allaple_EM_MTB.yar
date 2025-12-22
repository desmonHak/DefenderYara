
rule Worm_Win32_Allaple_EM_MTB{
	meta:
		description = "Worm:Win32/Allaple.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 59 44 72 6c 45 44 6e 67 } //1 EYDrlEDng
		$a_01_1 = {45 51 46 49 53 66 67 4f 48 } //1 EQFISfgOH
		$a_01_2 = {6c 71 43 64 4e 43 55 6a } //1 lqCdNCUj
		$a_01_3 = {77 52 4a 79 6d 6b 50 43 } //1 wRJymkPC
		$a_01_4 = {47 55 62 45 6f 76 5a 78 } //1 GUbEovZx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}