
rule Trojan_Win32_SuspLocalData_C{
	meta:
		description = "Trojan:Win32/SuspLocalData.C,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64 20 2d 55 72 69 } //Invoke-RestMethod -Uri  1
		$a_80_2 = {4f 75 74 2d 46 69 6c 65 } //Out-File  1
		$a_80_3 = {24 65 6e 76 3a 54 4d 50 } //$env:TMP  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}