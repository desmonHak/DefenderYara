
rule Trojan_Win32_Tofsee_PNB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 c2 00 00 10 00 c6 02 6b c6 42 01 65 c6 42 02 72 c6 42 03 6e c6 42 04 65 c6 42 05 6c c6 42 06 33 52 8d 05 } //4
		$a_00_1 = {71 6d 6b 6b 72 74 71 67 69 65 70 76 73 } //2 qmkkrtqgiepvs
		$a_00_2 = {68 72 69 74 65 50 72 6f 5f 5f 5f 5f 5f 65 5f 6f 72 79 } //2 hritePro_____e_ory
		$a_00_3 = {71 76 72 71 72 71 73 6c 73 6b 73 71 75 68 73 } //2 qvrqrqslsksquhs
		$a_01_4 = {51 29 d2 81 ca 88 06 00 00 52 29 ff 81 cf 88 06 00 00 57 29 c9 81 c9 00 00 04 00 51 ff 15 } //2
		$a_01_5 = {74 25 29 c0 48 23 03 f8 83 d3 04 f7 d0 83 e8 d8 01 d0 f8 83 d8 01 29 d2 29 c2 f7 da 50 8f 06 8d 76 04 8d 49 04 eb d3 5e 8d 15 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=13
 
}