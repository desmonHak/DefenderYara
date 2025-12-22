
rule Ransom_Linux_Monrans_A_MTB{
	meta:
		description = "Ransom:Linux/Monrans.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 77 69 70 65 53 65 6e 73 69 74 69 76 65 44 61 74 61 } //1 main.wipeSensitiveData
		$a_01_1 = {6d 61 69 6e 2e 65 6c 65 76 61 74 65 50 72 69 76 69 6c 65 67 65 73 } //1 main.elevatePrivileges
		$a_01_2 = {6d 61 69 6e 2e 64 69 73 61 62 6c 65 53 65 63 75 72 69 74 79 } //1 main.disableSecurity
		$a_01_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 53 68 61 64 6f 77 43 6f 70 69 65 73 } //1 main.encryptShadowCopies
		$a_01_4 = {6d 61 69 6e 2e 6b 69 6c 6c 50 72 6f 63 65 73 73 65 73 55 73 69 6e 67 46 69 6c 65 } //1 main.killProcessesUsingFile
		$a_01_5 = {6d 61 69 6e 2e 72 65 70 6f 72 74 45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 main.reportEncryptedFiles
		$a_01_6 = {6d 61 69 6e 2e 73 65 74 57 61 6c 6c 70 61 70 65 72 } //1 main.setWallpaper
		$a_01_7 = {2f 72 6f 6f 74 2f 6d 6f 6e 6b 65 79 72 61 6e 73 2f 6d 6f 6e 65 6b 65 79 2e 67 6f } //1 /root/monkeyrans/monekey.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}