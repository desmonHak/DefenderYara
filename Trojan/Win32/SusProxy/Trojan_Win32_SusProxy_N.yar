
rule Trojan_Win32_SusProxy_N{
	meta:
		description = "Trojan:Win32/SusProxy.N,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {47 66 78 44 6f 77 6e 6c 6f 61 64 57 72 61 70 70 65 72 2e 65 78 65 } //GfxDownloadWrapper.exe  1
		$a_80_3 = {47 66 78 44 6f 77 6e 6c 6f 61 64 57 72 61 70 70 65 72 2e 64 6c 6c } //GfxDownloadWrapper.dll  1
		$a_80_4 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 49 6e 74 65 6c 5c 47 61 6d 65 73 5c 73 65 74 74 69 6e 67 73 2e 64 6c 6c } //AppData\Local\Intel\Games\settings.dll  1
		$a_80_5 = {74 61 73 6b 6c 69 73 74 20 2f 73 76 63 20 7c 20 66 69 6e 64 73 74 72 20 2f 69 } //tasklist /svc | findstr /i  1
		$a_00_6 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 63 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98c0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_00_6  & 1)*-1) >=6
 
}