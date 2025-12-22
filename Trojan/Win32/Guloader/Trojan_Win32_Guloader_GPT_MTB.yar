
rule Trojan_Win32_Guloader_GPT_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 65 70 65 63 68 65 20 66 6f 72 76 69 73 65 72 20 69 6e 63 69 6e 65 72 61 74 65 64 } //1 depeche forviser incinerated
		$a_81_1 = {75 6e 62 75 6e 67 20 6d 69 6e 65 72 61 6c 69 73 61 74 69 6f 6e 20 66 65 72 72 79 6d 65 6e } //1 unbung mineralisation ferrymen
		$a_81_2 = {70 69 6c 66 65 72 65 72 2e 65 78 65 } //1 pilferer.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}