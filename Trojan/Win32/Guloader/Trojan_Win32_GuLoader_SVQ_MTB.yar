
rule Trojan_Win32_GuLoader_SVQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 55 6e 62 65 74 74 65 72 61 62 6c 65 39 38 5c 73 6d 72 67 61 61 73 65 6e } //1 \Unbetterable98\smrgaasen
		$a_81_1 = {5c 49 6e 74 65 72 6e 61 6c 69 7a 61 74 69 6f 6e 36 35 5c 55 6e 63 68 61 74 74 65 6c 65 64 2e 6a 70 67 } //1 \Internalization65\Unchatteled.jpg
		$a_81_2 = {5c 41 63 72 6f 73 74 6f 6c 69 6f 6e 34 37 5c 53 65 6d 69 70 61 6e 69 63 31 37 39 2e 6c 6e 6b } //1 \Acrostolion47\Semipanic179.lnk
		$a_81_3 = {42 61 6a 6f 6e 65 74 66 61 74 6e 69 6e 67 65 72 2e 64 6f 6e } //1 Bajonetfatninger.don
		$a_81_4 = {48 61 61 6e 64 74 61 73 6b 65 6e 73 2e 62 65 76 } //1 Haandtaskens.bev
		$a_81_5 = {49 6e 74 72 61 66 69 73 74 75 6c 61 72 2e 73 65 6c } //1 Intrafistular.sel
		$a_81_6 = {50 61 74 72 75 6c 6a 65 66 72 65 72 6e 65 73 2e 69 6e 69 } //1 Patruljefrernes.ini
		$a_81_7 = {68 65 74 65 72 6f 73 65 6b 73 75 61 6c 69 74 65 74 73 2e 73 6d 61 } //1 heteroseksualitets.sma
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}