
rule Trojan_Win32_SusDLLSearchOrderl_MK{
	meta:
		description = "Trojan:Win32/SusDLLSearchOrderl.MK,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {72 75 6e 64 6c 6c 33 32 } //rundll32  1
		$a_80_4 = {70 68 6f 6e 65 68 6f 6d 65 5f 6d 61 69 6e 20 } //phonehome_main   1
		$a_80_5 = {70 68 6f 6e 65 48 6f 6d 65 } //phoneHome  1
		$a_80_6 = {5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } //\\.\pipe\move  1
		$a_00_7 = {62 00 62 00 37 00 66 00 34 00 63 00 34 00 33 00 2d 00 66 00 36 00 32 00 62 00 2d 00 34 00 65 00 66 00 39 00 2d 00 38 00 64 00 30 00 34 00 2d 00 30 00 34 00 31 00 36 00 39 00 30 00 62 00 30 00 33 00 64 00 30 00 38 00 } //-1 bb7f4c43-f62b-4ef9-8d04-041690b03d08
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_00_7  & 1)*-1) >=7
 
}
rule Trojan_Win32_SusDLLSearchOrderl_MK_2{
	meta:
		description = "Trojan:Win32/SusDLLSearchOrderl.MK,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {72 75 6e 64 6c 6c 33 32 } //rundll32  1
		$a_80_4 = {70 68 6f 6e 65 68 6f 6d 65 5f 6d 61 69 6e 20 } //phonehome_main   1
		$a_80_5 = {70 68 6f 6e 65 48 6f 6d 65 } //phoneHome  1
		$a_80_6 = {5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } //\\.\pipe\move  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}