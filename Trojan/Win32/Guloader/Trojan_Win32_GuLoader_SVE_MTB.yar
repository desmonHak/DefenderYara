
rule Trojan_Win32_GuLoader_SVE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 72 6f 6d 61 6e 74 69 6b 65 72 73 5c 76 61 70 6f 72 69 7a 65 73 } //1 \romantikers\vaporizes
		$a_81_1 = {5c 65 66 66 65 72 76 65 73 63 65 6e 63 65 73 2e 62 69 6e } //1 \effervescences.bin
		$a_81_2 = {5c 67 79 74 6c 69 6e 67 2e 67 69 66 } //1 \gytling.gif
		$a_81_3 = {4b 65 6a 73 65 72 74 61 6e 6b 65 72 73 2e 73 63 68 } //1 Kejsertankers.sch
		$a_81_4 = {5c 6b 6c 61 73 73 65 75 6e 64 65 72 76 69 73 6e 69 6e 67 65 72 6e 65 2e 74 78 74 } //1 \klasseundervisningerne.txt
		$a_81_5 = {5c 50 6f 67 6f 6e 6f 70 68 6f 72 61 6e 5c 64 65 62 61 74 74 65 61 74 65 72 65 74 2e 6a 70 67 } //1 \Pogonophoran\debatteateret.jpg
		$a_81_6 = {5c 52 65 61 63 74 69 6f 6e 61 72 69 73 6d 2e 62 69 6e } //1 \Reactionarism.bin
		$a_81_7 = {5c 54 6f 6e 67 75 65 6c 69 6b 65 2e 7a 69 70 } //1 \Tonguelike.zip
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}