
rule Trojan_Win32_SuspProxy_J{
	meta:
		description = "Trojan:Win32/SuspProxy.J,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {69 65 66 72 61 6d 65 2e 64 6c 6c } //ieframe.dll  1
		$a_80_2 = {4f 70 65 6e 55 52 4c } //OpenURL  1
		$a_80_3 = {63 61 6c 63 2e 75 72 6c } //calc.url  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}