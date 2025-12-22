
rule Trojan_Win32_GuLoader_SVG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 4a 6f 6e 61 74 68 61 6e 69 7a 61 74 69 6f 6e 5c 74 6f 6e 69 6e 67 65 6e 73 2e 68 74 6d } //1 \Jonathanization\toningens.htm
		$a_81_1 = {5c 6b 72 69 74 69 6b 65 72 73 2e 69 6e 69 } //1 \kritikers.ini
		$a_81_2 = {6a 75 64 69 63 69 61 6c 69 74 79 2e 65 78 65 } //1 judiciality.exe
		$a_81_3 = {5c 42 6c 6f 64 70 72 6f 63 65 6e 74 65 72 6e 65 32 34 37 5c 6d 61 66 66 69 63 6b 2e 62 69 6e } //1 \Blodprocenterne247\maffick.bin
		$a_81_4 = {5c 6a 6f 75 72 6e 65 79 65 72 73 5c 69 6c 6d 61 72 63 68 65 72 2e 68 74 6d } //1 \journeyers\ilmarcher.htm
		$a_81_5 = {5c 50 6c 65 64 67 6f 72 73 35 38 5c 4e 78 2e 69 6e 69 } //1 \Pledgors58\Nx.ini
		$a_81_6 = {41 75 73 74 65 6e 69 74 69 7a 69 6e 67 2e 67 79 6d } //1 Austenitizing.gym
		$a_81_7 = {50 6f 70 75 6c 6f 75 73 6c 79 2e 79 70 70 } //1 Populously.ypp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}