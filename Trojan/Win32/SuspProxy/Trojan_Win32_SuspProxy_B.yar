
rule Trojan_Win32_SuspProxy_B{
	meta:
		description = "Trojan:Win32/SuspProxy.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {6d 73 68 74 61 2e 65 78 65 } //mshta.exe  1
		$a_80_1 = {70 75 62 6c 69 63 } //public  1
		$a_80_2 = {74 65 78 74 62 6f 78 4e 61 6d 65 4e 61 6d 65 73 70 61 63 65 2e 68 74 61 } //textboxNameNamespace.hta  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_4 = {73 74 61 72 74 2e 68 74 61 } //start.hta  1
		$a_00_5 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 6c 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98l0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=3
 
}
rule Trojan_Win32_SuspProxy_B_2{
	meta:
		description = "Trojan:Win32/SuspProxy.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {61 64 76 70 61 63 6b 2e 64 6c 6c } //advpack.dll  1
		$a_80_2 = {66 6f 6f 62 61 72 } //foobar  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}