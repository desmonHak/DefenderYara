
rule _#PUA_Block_Yantai{
	meta:
		description = "!#PUA:Block:Yantai,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 6b 61 6f 6c 61 } //1 SOFTWARE\kaola
		$a_01_1 = {74 6a 6b 61 6f 6c 61 2e 73 75 6c 61 6e 67 2e 63 6f 6d } //1 tjkaola.sulang.com
		$a_01_2 = {68 61 6f 31 32 33 4a 75 7a 69 42 72 6f 77 73 65 72 5c 68 61 6f 31 32 33 4a 75 7a 69 2e 65 78 65 } //1 hao123JuziBrowser\hao123Juzi.exe
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6b 61 6f 6c 61 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\kaola
		$a_01_4 = {6c 69 6a 69 75 6e 69 6e 73 74 61 6c 6c 2e 70 6e 67 } //-100 lijiuninstall.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*-100) >=2
 
}