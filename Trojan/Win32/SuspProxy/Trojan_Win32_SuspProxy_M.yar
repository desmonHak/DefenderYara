
rule Trojan_Win32_SuspProxy_M{
	meta:
		description = "Trojan:Win32/SuspProxy.M,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //powershell.exe -c Unblock-File  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {49 6e 76 6f 6b 65 2d 44 65 66 65 6e 64 65 72 44 6f 77 6e 6c 6f 61 64 2e 70 73 31 } //Invoke-DefenderDownload.ps1  1
		$a_80_3 = {64 65 66 65 6e 64 65 72 5f 74 65 73 74 2e 74 78 74 3a 41 44 53 2e 65 78 65 } //defender_test.txt:ADS.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}