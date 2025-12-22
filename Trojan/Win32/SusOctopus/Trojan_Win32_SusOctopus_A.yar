
rule Trojan_Win32_SusOctopus_A{
	meta:
		description = "Trojan:Win32/SusOctopus.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //Unblock-File  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_3 = {6f 63 74 6f 70 75 73 49 6e 66 6f 47 61 74 68 65 72 2e 70 73 31 } //octopusInfoGather.ps1  1
		$a_00_4 = {65 00 66 00 39 00 30 00 34 00 34 00 62 00 32 00 2d 00 63 00 32 00 61 00 62 00 2d 00 34 00 62 00 34 00 33 00 2d 00 39 00 31 00 64 00 35 00 2d 00 62 00 62 00 35 00 61 00 65 00 64 00 64 00 63 00 34 00 64 00 37 00 36 00 } //-1 ef9044b2-c2ab-4b43-91d5-bb5aeddc4d76
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*-1) >=4
 
}