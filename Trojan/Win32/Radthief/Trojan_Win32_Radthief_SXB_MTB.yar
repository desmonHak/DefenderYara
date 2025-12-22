
rule Trojan_Win32_Radthief_SXB_MTB{
	meta:
		description = "Trojan:Win32/Radthief.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 cd 88 d6 88 d3 80 f5 ?? 20 c6 08 fd 20 f3 30 d6 08 de 30 ee 88 cd } //3
		$a_03_1 = {0f 9f c4 83 f9 ?? 88 d5 0f 9c c1 0f 9c 85 ?? ?? ?? ?? 20 e5 20 c1 } //2
		$a_80_2 = {4e 6f 20 6d 61 70 70 65 64 20 64 72 69 76 65 20 5a 3a 20 66 6f 75 6e 64 } //No mapped drive Z: found  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1) >=6
 
}