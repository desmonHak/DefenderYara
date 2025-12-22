
rule Trojan_Win32_SusDisco_C{
	meta:
		description = "Trojan:Win32/SusDisco.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f } //cmd.exe /c echo  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {73 65 63 72 65 74 2e 74 78 74 } //secret.txt  1
		$a_00_3 = {64 00 66 00 39 00 30 00 34 00 34 00 62 00 32 00 2d 00 63 00 32 00 61 00 62 00 2d 00 34 00 62 00 34 00 33 00 2d 00 39 00 31 00 64 00 35 00 2d 00 62 00 62 00 35 00 61 00 65 00 64 00 64 00 63 00 34 00 64 00 37 00 36 00 } //-1 df9044b2-c2ab-4b43-91d5-bb5aeddc4d76
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}