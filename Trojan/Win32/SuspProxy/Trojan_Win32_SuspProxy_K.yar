
rule Trojan_Win32_SuspProxy_K{
	meta:
		description = "Trojan:Win32/SuspProxy.K,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {61 64 76 70 61 63 6b 2e 64 6c 6c } //advpack.dll  1
		$a_80_2 = {23 2b 31 32 20 63 61 6c 63 2e 65 78 65 } //#+12 calc.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}