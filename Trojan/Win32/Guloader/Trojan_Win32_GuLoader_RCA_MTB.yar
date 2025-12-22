
rule Trojan_Win32_GuLoader_RCA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 55 6e 64 65 72 74 72 79 6b 6b 65 6c 73 65 73 5c 62 61 63 61 6c 61 6f 5c 42 69 70 65 6c 74 61 74 65 31 38 33 } //1 \Undertrykkelses\bacalao\Bipeltate183
		$a_81_1 = {65 65 79 75 63 68 5c 4c 69 74 68 6f 74 72 65 73 69 73 32 31 35 5c 74 61 6e 6b 61 6e 67 72 65 62 65 74 73 } //1 eeyuch\Lithotresis215\tankangrebets
		$a_81_2 = {39 39 5c 6f 6e 6c 6f 6f 6b 65 72 73 5c 71 6f 68 65 6c 65 74 68 2e 69 6e 69 } //1 99\onlookers\qoheleth.ini
		$a_81_3 = {25 72 65 6c 61 62 65 6c 65 72 25 5c 50 69 62 6c 6f 6b 74 6f 73 5c 75 6c 64 74 72 6a 65 72 } //1 %relabeler%\Pibloktos\uldtrjer
		$a_81_4 = {2d 5c 4f 70 66 69 6e 64 73 6f 6d 73 74 65 2e 65 78 65 } //1 -\Opfindsomste.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}