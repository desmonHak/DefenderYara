
rule Trojan_Win32_GuLoader_RDP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 67 75 72 67 75 6c 61 74 69 6f 6e 5c 62 75 66 66 6f 6f 6e 65 72 69 65 73 5c 63 6f 6e 76 65 72 74 65 72 6e 65 } //1 \gurgulation\buffooneries\converterne
		$a_81_1 = {68 65 69 67 68 74 65 6e 73 5c 65 6e 67 61 6e 67 73 73 6b 61 74 5c } //1 heightens\engangsskat\
		$a_81_2 = {5c 63 6f 61 70 70 65 61 72 5c 48 61 67 62 6f 61 74 2e 62 69 6e } //1 \coappear\Hagboat.bin
		$a_81_3 = {5c 61 72 65 64 5c 4c 65 6d 6d 65 72 6e 65 73 2e 69 6e 69 } //1 \ared\Lemmernes.ini
		$a_81_4 = {5c 57 69 6c 64 65 72 6c 61 6e 64 5c 68 65 6d 69 61 74 61 78 79 2e 65 78 65 } //1 \Wilderland\hemiataxy.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RDP_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 43 68 75 74 7a 70 61 73 31 34 31 5c 43 68 61 72 67 65 61 62 6c 79 33 31 } //1 \Chutzpas141\Chargeably31
		$a_81_1 = {5c 73 75 62 6f 62 73 63 75 72 65 6e 65 73 73 5c 47 72 6f 75 6e 64 77 61 72 64 2e 69 6e 69 } //1 \subobscureness\Groundward.ini
		$a_81_2 = {5c 54 65 6b 73 74 6e 64 72 69 6e 67 65 72 6e 65 2e 62 69 6e } //1 \Tekstndringerne.bin
		$a_81_3 = {25 66 72 65 6c 73 65 72 73 6f 6c 64 61 74 25 5c 48 6f 72 6e 6d 75 73 69 6b 5c 61 76 69 73 65 72 65 72 } //1 %frelsersoldat%\Hornmusik\aviserer
		$a_81_4 = {5c 69 6e 74 65 72 70 65 6c 6c 65 72 65 6e 64 65 73 2e 6a 70 67 } //1 \interpellerendes.jpg
		$a_81_5 = {5c 66 6a 65 72 6b 72 66 61 72 6d 65 5c 73 69 6b 73 74 75 73 2e 65 78 65 } //1 \fjerkrfarme\sikstus.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}