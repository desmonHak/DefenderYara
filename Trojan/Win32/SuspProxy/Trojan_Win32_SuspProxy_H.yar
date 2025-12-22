
rule Trojan_Win32_SuspProxy_H{
	meta:
		description = "Trojan:Win32/SuspProxy.H,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 46 73 73 5c 46 69 6c 65 53 79 6e 63 53 68 65 6c 6c 36 34 2e 64 6c 6c } //AppData\Local\Microsoft\EdgeFss\FileSyncShell64.dll  1
		$a_00_2 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 72 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98r0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}
rule Trojan_Win32_SuspProxy_H_2{
	meta:
		description = "Trojan:Win32/SuspProxy.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {75 72 6c 2c 4f 70 65 6e 55 52 4c 20 66 69 6c 65 3a } //url,OpenURL file:  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_3 = {61 64 6f 62 65 2e 65 78 65 } //adobe.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}