
rule Trojan_Win32_SuspScripting_MK{
	meta:
		description = "Trojan:Win32/SuspScripting.MK,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {4c 6f 63 6b 4c 65 73 73 2e 65 78 65 } //LockLess.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {57 65 62 43 61 63 68 65 56 30 31 2e 64 61 74 } //WebCacheV01.dat  1
		$a_80_3 = {74 61 73 6b 68 6f 73 74 77 } //taskhostw  1
		$a_80_4 = {6f 75 74 2e 74 6d 70 } //out.tmp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}