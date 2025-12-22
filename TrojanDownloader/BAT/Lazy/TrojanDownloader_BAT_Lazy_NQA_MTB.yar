
rule TrojanDownloader_BAT_Lazy_NQA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Lazy.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 6f 64 65 42 61 73 65 36 34 54 6f 55 72 6c } //2 DecodeBase64ToUrl
		$a_81_1 = {66 34 63 36 64 61 39 65 2d 35 62 65 36 2d 34 35 31 62 2d 38 35 37 66 2d 36 30 66 31 37 30 62 30 61 62 61 37 } //1 f4c6da9e-5be6-451b-857f-60f170b0aba7
		$a_81_2 = {50 61 72 73 65 43 6f 6e 66 69 67 46 69 6c 65 } //1 ParseConfigFile
		$a_81_3 = {47 65 74 46 69 6c 65 4e 61 6d 65 46 72 6f 6d 55 72 6c } //1 GetFileNameFromUrl
		$a_81_4 = {44 65 63 6f 6d 70 72 65 73 73 46 69 6c 65 } //1 DecompressFile
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {62 61 73 65 36 34 55 72 6c } //1 base64Url
		$a_81_7 = {44 6f 77 6e 41 70 } //1 DownAp
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}