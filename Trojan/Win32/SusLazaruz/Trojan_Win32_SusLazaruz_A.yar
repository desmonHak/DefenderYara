
rule Trojan_Win32_SusLazaruz_A{
	meta:
		description = "Trojan:Win32/SusLazaruz.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 57 2d 47 65 74 44 72 69 76 65 54 79 70 65 2e 65 78 65 } //GetLogicalDriveStringsW-GetDriveType.exe  1
		$a_80_1 = {25 54 4d 50 25 } //%TMP%  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}