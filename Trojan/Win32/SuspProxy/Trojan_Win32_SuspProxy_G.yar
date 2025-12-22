
rule Trojan_Win32_SuspProxy_G{
	meta:
		description = "Trojan:Win32/SuspProxy.G,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {6d 73 69 65 78 65 63 2e 65 78 65 20 2f 71 20 2f 69 } //msiexec.exe /q /i  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {69 6e 2e 73 79 73 } //in.sys  1
		$a_00_3 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 71 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98q0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SuspProxy_G_2{
	meta:
		description = "Trojan:Win32/SuspProxy.G,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 } //cmd.exe /c copy  1
		$a_80_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_3 = {61 64 6f 62 65 2e 65 78 65 } //adobe.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}