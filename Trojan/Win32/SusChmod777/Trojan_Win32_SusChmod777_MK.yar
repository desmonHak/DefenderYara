
rule Trojan_Win32_SusChmod777_MK{
	meta:
		description = "Trojan:Win32/SusChmod777.MK,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {69 63 61 63 6c 73 } //icacls  1
		$a_80_4 = {73 62 64 2e 62 69 6e } //sbd.bin  1
		$a_80_5 = {2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 } ///grant Everyone:F  1
		$a_00_6 = {64 00 74 00 37 00 66 00 34 00 63 00 34 00 33 00 2d 00 66 00 36 00 32 00 62 00 2d 00 34 00 65 00 66 00 39 00 2d 00 38 00 64 00 30 00 34 00 2d 00 30 00 34 00 31 00 36 00 39 00 30 00 62 00 30 00 33 00 64 00 30 00 39 00 } //-1 dt7f4c43-f62b-4ef9-8d04-041690b03d09
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_00_6  & 1)*-1) >=6
 
}
rule Trojan_Win32_SusChmod777_MK_2{
	meta:
		description = "Trojan:Win32/SusChmod777.MK,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {69 63 61 63 6c 73 } //icacls  1
		$a_80_4 = {73 62 64 2e 62 69 6e } //sbd.bin  1
		$a_80_5 = {2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 } ///grant Everyone:F  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}