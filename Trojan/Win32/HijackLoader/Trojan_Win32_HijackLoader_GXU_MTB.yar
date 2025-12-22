
rule Trojan_Win32_HijackLoader_GXU_MTB{
	meta:
		description = "Trojan:Win32/HijackLoader.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 40 89 45 ec 8b 45 ec 3b 45 e4 7d 1c 8b 45 e4 48 2b 45 ec 8b 4d f8 03 4d fc 8a 44 05 b4 88 01 8b 45 fc 40 89 45 fc } //10
		$a_01_1 = {5c 54 65 6d 70 5c 57 65 62 20 44 61 74 61 } //1 \Temp\Web Data
		$a_01_2 = {5c 54 65 6d 70 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Temp\Login Data
		$a_01_3 = {5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 43 6f 6f 6b 69 65 73 } //1 \Local\Temp\Cookies
		$a_01_4 = {63 6f 6e 66 69 67 5c 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //1 config\loginusers.vdf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}