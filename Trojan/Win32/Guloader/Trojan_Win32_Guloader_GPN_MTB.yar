
rule Trojan_Win32_Guloader_GPN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 75 72 65 6e 69 6e 67 73 73 61 67 73 20 66 72 75 65 66 72 61 6b 6b 65 72 } //1 forureningssags fruefrakker
		$a_81_1 = {68 69 73 73 65 74 } //1 hisset
		$a_81_2 = {65 72 68 6f 6c 64 20 65 6d 75 6c 61 62 6c 65 2e 65 78 65 } //1 erhold emulable.exe
		$a_81_3 = {69 73 66 6c 61 67 65 72 } //1 isflager
		$a_81_4 = {61 70 74 79 63 68 75 73 20 6f 6c 79 6d 70 69 63 20 68 75 72 74 69 67 74 72 72 65 6e 64 65 } //1 aptychus olympic hurtigtrrende
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}