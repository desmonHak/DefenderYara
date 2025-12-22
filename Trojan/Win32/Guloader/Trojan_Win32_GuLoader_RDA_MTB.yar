
rule Trojan_Win32_GuLoader_RDA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 72 75 64 65 70 61 72 73 5c 65 74 61 61 72 73 66 64 73 65 6c 73 64 61 67 65 6e 73 5c 64 6b 73 62 61 61 64 65 6e } //1 brudepars\etaarsfdselsdagens\dksbaaden
		$a_81_1 = {25 42 65 76 6f 6d 69 74 65 64 32 35 25 5c 4d 61 72 6b 65 64 73 75 64 76 69 6b 6c 69 6e 67 31 32 32 5c 70 72 69 6e 74 65 72 73 6b 72 69 66 74 } //1 %Bevomited25%\Markedsudvikling122\printerskrift
		$a_81_2 = {37 5c 6e 65 63 65 73 73 69 73 6d 5c 70 65 63 74 6f 73 61 73 65 2e 6c 6e 6b } //1 7\necessism\pectosase.lnk
		$a_81_3 = {38 38 5c 72 65 63 74 61 6e 67 6c 65 5c 42 72 61 73 69 65 72 2e 69 6e 69 } //1 88\rectangle\Brasier.ini
		$a_81_4 = {28 28 5c 67 6e 61 73 6b 65 72 69 65 72 6e 65 5c 67 6c 65 6d 6d 65 62 6f 67 2e 65 78 65 } //1 ((\gnaskerierne\glemmebog.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}