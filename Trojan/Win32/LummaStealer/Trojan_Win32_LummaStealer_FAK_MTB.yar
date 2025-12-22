
rule Trojan_Win32_LummaStealer_FAK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c4 32 5d ff 8b 55 c8 30 18 8b 5d 14 8b 45 08 3b 4d 0c 72 a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_LummaStealer_FAK_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.FAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 68 65 6d 69 64 61 } //1 Themida
		$a_81_1 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //1 %userappdata%\RestartApp.exe
		$a_81_2 = {5c 5c 2e 5c 4f 72 65 61 6e 73 2e 76 78 64 } //1 \\.\Oreans.vxd
		$a_03_3 = {50 45 00 00 4c 01 06 00 3f 0a b7 68 00 00 00 00 00 00 00 00 e0 00 02 01 0b 01 0e 00 00 f0 04 00 00 9a 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 00 00 40 00 00 10 00 00 00 02 00 00 06 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 ?? ?? 00 00 04 } //10
		$a_01_4 = {20 20 20 00 20 20 20 20 00 e0 05 00 00 10 00 00 00 e0 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 } //10
		$a_01_5 = {c0 02 00 00 00 f0 05 00 00 02 00 00 00 f0 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 } //10
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=33
 
}