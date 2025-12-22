
rule Trojan_Win32_SuspSetting_H{
	meta:
		description = "Trojan:Win32/SuspSetting.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {4e 65 77 2d 4f 62 6a 65 63 74 } //New-Object  1
		$a_80_2 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 2e 4d 75 74 65 78 28 } //System.Threading.Mutex(  1
		$a_80_3 = {44 69 73 70 6f 73 65 28 29 } //Dispose()  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}