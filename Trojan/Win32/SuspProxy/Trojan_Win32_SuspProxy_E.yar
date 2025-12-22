
rule Trojan_Win32_SuspProxy_E{
	meta:
		description = "Trojan:Win32/SuspProxy.E,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {6f 72 6d 61 74 20 25 53 59 53 54 45 4d 44 52 49 56 45 25 } //ormat %SYSTEMDRIVE%  1
		$a_80_3 = {2f 66 73 3a 4e 50 52 75 6e 6e 65 72 } ///fs:NPRunner  1
		$a_00_4 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 6f 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98o0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*-1) >=4
 
}
rule Trojan_Win32_SuspProxy_E_2{
	meta:
		description = "Trojan:Win32/SuspProxy.E,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {74 74 74 72 61 63 65 72 2e 65 78 65 } //tttracer.exe  1
		$a_80_1 = {63 61 6c 63 2e 65 78 65 } //calc.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}