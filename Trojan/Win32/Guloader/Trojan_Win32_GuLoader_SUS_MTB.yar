
rule Trojan_Win32_GuLoader_SUS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 67 6e 69 64 65 72 69 65 72 6e 65 } //1 \gniderierne
		$a_81_1 = {5c 6d 65 64 69 63 6f 70 68 79 73 69 63 61 6c 2e 74 78 74 } //1 \medicophysical.txt
		$a_81_2 = {5c 72 6f 74 74 65 66 6c 64 65 5c 61 6e 6c 67 73 6a 65 6d 65 64 65 6e 65 2e 65 78 65 } //1 \rotteflde\anlgsjemedene.exe
		$a_81_3 = {5c 70 68 69 6c 6f 6d 61 74 68 79 2e 67 69 66 } //1 \philomathy.gif
		$a_81_4 = {5c 61 73 74 6d 61 6c 67 65 72 6e 65 73 5c 6a 61 67 74 62 64 65 73 2e 62 69 6e } //1 \astmalgernes\jagtbdes.bin
		$a_81_5 = {5c 6e 6f 72 64 65 75 72 6f 70 69 73 6b 65 2e 65 78 65 } //1 \nordeuropiske.exe
		$a_81_6 = {5c 65 6c 69 74 65 6b 6f 72 70 73 2e 64 6c 6c } //1 \elitekorps.dll
		$a_81_7 = {5c 6b 61 6c 61 64 61 6e 61 5c 73 74 61 62 6c 65 6e 64 65 73 2e 62 69 6e } //1 \kaladana\stablendes.bin
		$a_81_8 = {4e 61 76 69 67 61 62 65 6c 2e 6a 70 67 } //1 Navigabel.jpg
		$a_81_9 = {62 61 72 69 61 74 72 69 63 73 2e 69 6e 69 } //1 bariatrics.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}