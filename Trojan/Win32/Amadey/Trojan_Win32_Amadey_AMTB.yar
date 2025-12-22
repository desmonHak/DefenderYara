
rule Trojan_Win32_Amadey_AMTB{
	meta:
		description = "Trojan:Win32/Amadey!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 35 65 34 38 65 37 38 2d 32 39 35 31 2d 34 31 31 37 2d 62 38 30 36 2d 65 34 66 38 65 36 32 36 66 32 38 63 } //d5e48e78-2951-4117-b806-e4f8e626f28c  2
		$a_80_1 = {36 35 2e 31 30 39 2e 31 2e 32 32 38 } //65.109.1.228  2
		$a_80_2 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 57 65 62 20 44 61 74 61 } //\AppData\Local\Temp\Web Data  2
		$a_80_3 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\AppData\Local\Temp\Login Data  2
		$a_80_4 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 43 6f 6f 6b 69 65 73 } //\AppData\Local\Temp\Cookies  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}