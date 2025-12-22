
rule Trojan_Win32_SuspAAD_D{
	meta:
		description = "Trojan:Win32/SuspAAD.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {71 62 6f 74 44 69 73 63 6f 76 65 72 79 2e 62 61 74 } //qbotDiscovery.bat  1
		$a_00_3 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 78 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98x0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SuspAAD_D_2{
	meta:
		description = "Trojan:Win32/SuspAAD.D,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {52 65 63 6f 6e 65 72 61 74 6f 72 2e 65 78 65 } //Reconerator.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}