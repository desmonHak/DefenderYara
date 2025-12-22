
rule Trojan_Win32_Guloader_GPL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6b 6f 6e 74 72 61 64 69 6b 74 69 6f 6e 65 72 73 20 6d 65 72 63 75 72 69 61 6c 69 74 79 20 63 61 74 65 63 68 69 73 74 73 } //1 kontradiktioners mercuriality catechists
		$a_81_1 = {6b 62 73 74 61 64 62 6f 65 72 73 20 74 69 6c 6d 61 61 6c 69 6e 67 20 68 6f 6e 6f 72 72 } //1 kbstadboers tilmaaling honorr
		$a_81_2 = {6d 69 6e 69 73 75 72 76 65 79 73 2e 65 78 65 } //1 minisurveys.exe
		$a_81_3 = {65 6b 73 61 6d 69 6e 61 74 6f 72 73 20 61 75 74 6f 72 69 74 61 74 69 76 65 72 65 20 6d 69 6e 6f 6e 61 } //1 eksaminators autoritativere minona
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}