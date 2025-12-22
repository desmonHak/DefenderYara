
rule Trojan_Win32_SusPrivChecks_A{
	meta:
		description = "Trojan:Win32/SusPrivChecks.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //Unblock-File  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_3 = {49 6e 76 6f 6b 65 2d 50 72 69 76 65 73 63 43 68 65 63 6b } //Invoke-PrivescCheck  1
		$a_80_4 = {49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 } //Import-Module  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}