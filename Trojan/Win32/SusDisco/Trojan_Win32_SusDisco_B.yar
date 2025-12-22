
rule Trojan_Win32_SusDisco_B{
	meta:
		description = "Trojan:Win32/SusDisco.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {2f 41 6c 6c 6f 77 55 6e 73 61 66 65 } ///AllowUnsafe  1
		$a_80_2 = {53 69 74 52 65 70 2e 65 78 65 } //SitRep.exe  1
		$a_00_3 = {62 00 66 00 39 00 30 00 34 00 34 00 62 00 32 00 2d 00 63 00 32 00 61 00 62 00 2d 00 34 00 62 00 34 00 33 00 2d 00 39 00 31 00 64 00 35 00 2d 00 62 00 62 00 35 00 61 00 65 00 64 00 64 00 63 00 34 00 64 00 37 00 36 00 } //-1 bf9044b2-c2ab-4b43-91d5-bb5aeddc4d76
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}