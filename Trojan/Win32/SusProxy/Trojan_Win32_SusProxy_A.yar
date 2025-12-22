
rule Trojan_Win32_SusProxy_A{
	meta:
		description = "Trojan:Win32/SusProxy.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {75 72 6c 2e 64 6c 6c } //url.dll  1
		$a_80_2 = {46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //FileProtocolHandler  1
		$a_00_3 = {61 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 70 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 61 00 } //-1 a453e881-26a8-4973-bp2e-76269e901d0a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}