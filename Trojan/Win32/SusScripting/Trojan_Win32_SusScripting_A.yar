
rule Trojan_Win32_SusScripting_A{
	meta:
		description = "Trojan:Win32/SusScripting.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //powershell.exe -c Unblock-File  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {49 6e 76 6f 6b 65 2d 53 79 73 69 6e 66 6f } //Invoke-Sysinfo  1
		$a_80_3 = {49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 } //Import-Module  1
		$a_80_4 = {2d 50 73 48 69 73 74 6f 72 79 } //-PsHistory  1
		$a_00_5 = {39 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 61 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 76 00 } //-1 9453e881-26a8-4973-ba2e-76269e901d0v
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=4
 
}