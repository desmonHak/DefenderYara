
rule Trojan_Win32_FileFix_HHG_MTB{
	meta:
		description = "Trojan:Win32/FileFix.HHG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_1 = {2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 } //1 -outfile
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FileFix_HHG_MTB_2{
	meta:
		description = "Trojan:Win32/FileFix.HHG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 47 00 65 00 74 00 46 00 6f 00 6c 00 64 00 65 00 72 00 50 00 61 00 74 00 68 00 } //1 [Environment]::GetFolderPath
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_2 = {7c 00 47 00 65 00 74 00 2d 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 20 00 2d 00 43 00 6f 00 75 00 6e 00 74 00 } //1 |Get-Random -Count
		$a_00_3 = {7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 } //1 {[char]$_
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}