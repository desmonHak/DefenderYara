
rule Trojan_Win32_SuspDisco_D{
	meta:
		description = "Trojan:Win32/SuspDisco.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {73 65 63 72 65 74 2e 74 78 74 } //secret.txt  1
		$a_80_3 = {77 6d 69 63 20 6f 73 20 67 65 74 20 42 75 69 6c 64 4e 75 6d 62 65 72 20 3e 3e } //wmic os get BuildNumber >>  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}