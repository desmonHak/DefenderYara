
rule Trojan_AndroidOS_Mamont_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 6c 79 66 61 6e 73 2f 4e 5a 54 54 72 61 6e 73 70 6f 72 74 24 73 65 6e 64 4e 65 77 49 6e 73 74 61 6c 6c } //1 onlyfans/NZTTransport$sendNewInstall
		$a_01_1 = {64 63 69 6d 46 69 6c 65 4c 69 73 74 } //1 dcimFileList
		$a_01_2 = {6f 6e 6c 79 66 61 6e 73 2e 4e 5a 54 54 72 61 6e 73 70 6f 72 74 } //1 onlyfans.NZTTransport
		$a_01_3 = {67 65 74 47 61 6c 6c 65 72 79 43 61 6d 65 72 61 49 6d 61 67 65 73 } //1 getGalleryCameraImages
		$a_01_4 = {67 65 74 4f 6e 65 43 61 6d 65 72 61 50 68 6f 74 6f } //1 getOneCameraPhoto
		$a_01_5 = {6f 6e 6c 79 66 61 6e 73 2f 4e 5a 54 54 72 61 6e 73 70 6f 72 74 24 73 65 6e 64 48 74 74 70 50 6f 73 74 46 69 6c 65 } //1 onlyfans/NZTTransport$sendHttpPostFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}