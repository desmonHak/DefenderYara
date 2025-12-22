
rule Trojan_Win32_SuspProxi_D{
	meta:
		description = "Trojan:Win32/SuspProxi.D,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 6c 62 } //AppData\Local\Temp\lb  1
		$a_80_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //Start-Process -FilePath  1
		$a_80_3 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 75 6e 72 65 67 6d 70 32 2e 65 78 65 } //Windows\System32\unregmp2.exe  1
		$a_80_4 = {2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 } //-ArgumentList  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}