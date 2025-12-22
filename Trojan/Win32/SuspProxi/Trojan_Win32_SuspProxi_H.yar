
rule Trojan_Win32_SuspProxi_H{
	meta:
		description = "Trojan:Win32/SuspProxi.H,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 46 73 73 5c 46 69 6c 65 53 79 6e 63 53 68 65 6c 6c 36 34 2e 64 6c 6c } //AppData\Local\Microsoft\EdgeFss\FileSyncShell64.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}