
rule Trojan_Win32_Zusy_BAD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 88 85 ?? ?? ?? ?? 0f b7 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 8d 4c 10 2b 88 8d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zusy_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 4c 10 00 00 10 00 00 00 90 08 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 } //10
		$a_01_1 = {84 5d 8d 00 00 60 10 00 00 e0 7a 00 00 a0 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 } //10
		$a_01_2 = {8a 79 07 00 00 c0 9d 00 00 70 00 00 00 80 83 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //10
		$a_81_3 = {73 68 6f 77 63 6f 64 65 } //1 showcode
		$a_81_4 = {63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //1 checkprotection
		$a_81_5 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 4c 69 63 65 6e 73 65 } //1 SOFTWARE\WinLicense
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=33
 
}