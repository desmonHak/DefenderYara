
rule Ransom_Win32_Filecoder_EYTO_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.EYTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_2 = {73 68 75 74 64 6f 77 6e 20 2f 73 } //1 shutdown /s
		$a_81_3 = {25 6d 2f 25 64 2f 25 79 } //1 %m/%d/%y
		$a_81_4 = {72 61 6e 64 6f 6d 5f 64 65 76 69 63 65 } //1 random_device
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}