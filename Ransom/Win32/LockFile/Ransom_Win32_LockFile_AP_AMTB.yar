
rule Ransom_Win32_LockFile_AP_AMTB{
	meta:
		description = "Ransom:Win32/LockFile.AP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {46 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 69 6d 61 67 65 } //Files are encrypted and injected into image  1
		$a_80_1 = {41 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 20 77 69 74 68 20 74 68 65 20 76 69 63 74 69 6d 20 49 44 20 69 73 20 70 6c 61 63 65 64 20 69 6e 20 65 61 63 68 20 74 61 72 67 65 74 65 64 20 64 69 72 65 63 74 6f 72 79 } //A ransom note with the victim ID is placed in each targeted directory  1
		$a_80_2 = {42 65 66 6f 72 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 73 74 61 72 74 65 64 20 74 68 65 20 73 69 6e 67 6c 65 20 72 61 6e 73 6f 6d 6e 6f 74 65 20 69 73 20 63 72 65 61 74 65 64 20 69 6e 20 74 68 65 20 72 6f 6f 74 20 64 69 72 65 63 74 6f 72 79 } //Before encryption started the single ransomnote is created in the root directory  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}