
rule Trojan_BAT_Xworm_EM_MTB{
	meta:
		description = "Trojan:BAT/Xworm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
		$a_81_1 = {44 33 44 53 43 61 63 68 65 } //1 D3DSCache
		$a_81_2 = {68 61 63 6b 65 72 36 36 36 6c 67 62 74 } //1 hacker666lgbt
		$a_81_3 = {6d 61 69 6e 2e 65 78 65 } //1 main.exe
		$a_81_4 = {66 6f 6e 74 64 72 76 68 6f 73 74 2e 65 78 65 } //1 fontdrvhost.exe
		$a_81_5 = {64 6c 6c 68 6f 73 74 2e 65 78 65 } //1 dllhost.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}