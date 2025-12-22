
rule Trojan_Win32_SusProxy_C{
	meta:
		description = "Trojan:Win32/SusProxy.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 68 6f 73 74 2e 65 78 65 } //conhost.exe  1
		$a_80_1 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //notepad.exe  1
		$a_00_2 = {61 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 72 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 61 00 } //-1 a453e881-26a8-4973-br2e-76269e901d0a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}