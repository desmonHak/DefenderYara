
rule Trojan_Win32_SusWebSessionCookie_MK{
	meta:
		description = "Trojan:Win32/SusWebSessionCookie.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {26 20 63 6f 70 79 } //& copy  1
		$a_80_4 = {5c 55 73 65 72 20 44 61 74 61 5c } //\User Data\  1
		$a_00_5 = {62 00 61 00 30 00 36 00 65 00 33 00 39 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 32 00 66 00 } //-1 ba06e39e-7876-4ba3-beee-42bd80ff362f
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=5
 
}
rule Trojan_Win32_SusWebSessionCookie_MK_2{
	meta:
		description = "Trojan:Win32/SusWebSessionCookie.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {26 20 63 6f 70 79 } //& copy  1
		$a_80_4 = {5c 55 73 65 72 20 44 61 74 61 5c } //\User Data\  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}