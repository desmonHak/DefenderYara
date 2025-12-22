
rule Trojan_Win32_GuLoader_SUL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 52 65 69 6e 6a 75 72 65 73 5c 6d 65 64 73 65 6e 64 74 65 73 } //1 \Reinjures\medsendtes
		$a_81_1 = {5c 74 6f 6c 76 61 61 72 73 66 64 73 65 6c 73 64 61 67 65 6e 5c 66 65 73 74 75 67 65 6e } //1 \tolvaarsfdselsdagen\festugen
		$a_81_2 = {5c 73 74 65 6d 6d 65 6a 65 72 6e 73 5c 6b 61 74 6f 64 65 73 74 72 61 61 6c 65 72 6e 65 73 2e 68 74 6d } //1 \stemmejerns\katodestraalernes.htm
		$a_81_3 = {5c 47 61 6c 61 63 74 6f 63 65 6c 65 2e 69 6e 69 } //1 \Galactocele.ini
		$a_81_4 = {52 65 6d 72 6b 65 64 65 73 2e 73 69 73 } //1 Remrkedes.sis
		$a_81_5 = {42 72 75 64 66 6c 61 64 65 6e 2e 44 72 61 } //1 Brudfladen.Dra
		$a_81_6 = {4d 61 6c 65 72 69 75 64 73 74 69 6c 6c 69 6e 67 65 72 6e 65 39 38 2e 6a 70 67 } //1 Maleriudstillingerne98.jpg
		$a_81_7 = {5c 4f 74 74 61 76 61 73 5c 4b 72 6f 6e 65 72 6e 65 } //1 \Ottavas\Kronerne
		$a_81_8 = {73 74 61 72 74 62 6f 67 73 74 61 76 65 72 2e 62 69 6e } //1 startbogstaver.bin
		$a_81_9 = {5c 42 72 75 67 73 6b 6c 61 72 74 5c 64 61 74 61 73 6b 72 6d 65 2e 6c 6e 6b } //1 \Brugsklart\dataskrme.lnk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}