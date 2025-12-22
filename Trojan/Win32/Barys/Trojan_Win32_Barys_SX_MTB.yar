
rule Trojan_Win32_Barys_SX_MTB{
	meta:
		description = "Trojan:Win32/Barys.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 8e 40 02 00 00 8b c7 6b c0 ?? 03 c1 85 58 0c 74 ?? 8b 16 50 8b 42 4c 8b ce ff d0 } //3
		$a_03_1 = {74 14 8a 10 80 f2 ?? 80 c2 ?? 88 10 83 e9 ?? 83 c0 ?? 85 c9 75 ec } //2
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //1 \\.\PhysicalDrive
		$a_01_3 = {4d 53 4f 4c 45 41 63 74 69 76 61 74 69 6f 6e } //1 MSOLEActivation
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}