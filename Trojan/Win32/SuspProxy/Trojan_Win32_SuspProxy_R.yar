
rule Trojan_Win32_SuspProxy_R{
	meta:
		description = "Trojan:Win32/SuspProxy.R,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {63 6f 6d 44 6c 6c 2e 64 6c 6c } //comDll.dll  1
		$a_80_3 = {73 74 61 72 74 57 6f 72 6b 65 72 } //startWorker  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}