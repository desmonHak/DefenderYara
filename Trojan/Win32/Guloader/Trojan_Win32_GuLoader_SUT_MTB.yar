
rule Trojan_Win32_GuLoader_SUT_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 52 6f 65 73 75 6b 6b 65 72 65 74 73 32 33 5c 72 61 75 67 68 74 } //1 \Roesukkerets23\raught
		$a_81_1 = {41 63 65 74 6f 78 79 70 68 74 68 61 6c 69 64 65 31 32 34 2e 74 78 74 } //1 Acetoxyphthalide124.txt
		$a_81_2 = {41 72 74 65 74 34 35 2e 63 61 74 } //1 Artet45.cat
		$a_81_3 = {46 6f 72 73 6b 6e 69 6e 67 73 70 72 6f 6a 65 6b 74 65 72 73 31 30 32 2e 6a 70 67 } //1 Forskningsprojekters102.jpg
		$a_81_4 = {49 6e 73 75 70 70 72 65 73 73 69 62 69 6c 69 74 79 2e 69 6e 69 } //1 Insuppressibility.ini
		$a_81_5 = {65 66 74 65 72 62 65 68 61 6e 64 6c 65 6e 64 65 2e 6a 70 67 } //1 efterbehandlende.jpg
		$a_81_6 = {76 65 6c 74 69 6c 66 72 65 64 68 65 64 65 6e 2e 61 76 6c } //1 veltilfredheden.avl
		$a_81_7 = {5c 62 65 66 61 6c 6c 65 6e 5c 50 72 69 73 6c 61 67 73 2e 69 6e 69 } //1 \befallen\Prislags.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}