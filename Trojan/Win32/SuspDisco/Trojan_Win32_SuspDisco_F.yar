
rule Trojan_Win32_SuspDisco_F{
	meta:
		description = "Trojan:Win32/SuspDisco.F,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_1 = {47 65 74 2d 57 69 6e 53 79 73 74 65 6d 4c 6f 63 61 6c 65 } //Get-WinSystemLocale  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}