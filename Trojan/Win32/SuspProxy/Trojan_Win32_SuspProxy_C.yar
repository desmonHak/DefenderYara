
rule Trojan_Win32_SuspProxy_C{
	meta:
		description = "Trojan:Win32/SuspProxy.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6d 6b 64 69 72 } //cmd.exe /c mkdir  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 6c 62 5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 } //AppData\Local\Temp\lb\Windows Media Player  1
		$a_00_2 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 6d 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98m0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}
rule Trojan_Win32_SuspProxy_C_2{
	meta:
		description = "Trojan:Win32/SuspProxy.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 68 6f 73 74 2e 65 78 65 } //conhost.exe  1
		$a_80_1 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //notepad.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}