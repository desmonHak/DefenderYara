
rule Trojan_Win32_SuspProxi_E{
	meta:
		description = "Trojan:Win32/SuspProxi.E,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {6f 72 6d 61 74 20 25 53 59 53 54 45 4d 44 52 49 56 45 25 } //ormat %SYSTEMDRIVE%  1
		$a_80_3 = {2f 66 73 3a 4e 50 52 75 6e 6e 65 72 } ///fs:NPRunner  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}