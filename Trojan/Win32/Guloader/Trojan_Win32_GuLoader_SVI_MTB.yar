
rule Trojan_Win32_GuLoader_SVI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 67 65 6e 6e 65 6d 70 6c 6a 65 74 5c 42 72 79 6c 6c 75 70 73 64 61 67 } //1 \gennempljet\Bryllupsdag
		$a_81_1 = {5c 42 6c 6f 6b 6e 69 6e 67 65 6e 73 5c 75 62 61 72 6d 68 6a 65 72 74 69 67 68 65 64 65 6e 2e 67 69 66 } //1 \Blokningens\ubarmhjertigheden.gif
		$a_81_2 = {44 65 72 6f 67 61 74 69 76 65 2e 55 6e 72 } //1 Derogative.Unr
		$a_81_3 = {44 72 69 66 74 73 62 69 64 72 61 67 2e 69 6e 69 } //1 Driftsbidrag.ini
		$a_81_4 = {48 69 63 63 6f 75 67 68 73 35 2e 6a 70 67 } //1 Hiccoughs5.jpg
		$a_81_5 = {50 72 6f 70 6f 72 74 2e 72 65 67 } //1 Proport.reg
		$a_81_6 = {5c 4b 61 6e 64 65 6c 61 62 72 65 6e 65 5c 54 69 72 65 72 6e 65 73 39 37 5c 50 61 61 73 65 65 6e 64 65 } //1 \Kandelabrene\Tirernes97\Paaseende
		$a_81_7 = {68 6f 76 65 64 73 74 61 64 73 6f 6d 72 61 61 64 65 74 73 2e 70 6f 74 } //1 hovedstadsomraadets.pot
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}