
rule Trojan_Win32_FileFix_HHC_MTB{
	meta:
		description = "Trojan:Win32/FileFix.HHC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2e 00 61 00 73 00 70 00 78 00 [0-3c] 20 00 23 00 } //1
		$a_00_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 68 00 74 00 74 00 70 00 } //1 Start-Process http
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_FileFix_HHC_MTB_2{
	meta:
		description = "Trojan:Win32/FileFix.HHC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 53 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 28 00 24 00 5f 00 } //1 .Substring($($_
		$a_00_1 = {2d 00 6a 00 6f 00 69 00 6e 00 } //1 -join
		$a_00_2 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 ForEach-Object
		$a_00_3 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 5b 00 69 00 6e 00 74 00 5d 00 } //1 [char]([int]
		$a_00_4 = {67 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 get-content
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_FileFix_HHC_MTB_3{
	meta:
		description = "Trojan:Win32/FileFix.HHC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 .GetString($convert::FromBase64String
		$a_00_1 = {3b 00 26 00 28 00 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 } //1 ;&(bitsadmin.exe /transfer 
		$a_00_2 = {6a 00 6f 00 69 00 6e 00 28 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 join($env:TEMP
		$a_00_3 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 .GetString($
		$a_00_4 = {2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //1 .GetBytes($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}