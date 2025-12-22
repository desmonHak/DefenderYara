
rule Trojan_PowerShell_SuspDownloadExecEncryptedFile_A{
	meta:
		description = "Trojan:PowerShell/SuspDownloadExecEncryptedFile.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 } //1  hidden 
		$a_00_2 = {20 00 2d 00 65 00 6e 00 63 00 20 00 24 00 } //1  -enc $
		$a_00_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 .downloadString
		$a_00_4 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 77 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 New-Object System.Net.webClient
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}