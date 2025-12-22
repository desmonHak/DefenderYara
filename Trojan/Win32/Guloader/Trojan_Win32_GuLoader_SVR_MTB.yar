
rule Trojan_Win32_GuLoader_SVR_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 42 6f 6c 69 76 69 61 6e 65 72 65 6e 73 35 37 2e 62 69 6e } //1 \Bolivianerens57.bin
		$a_81_1 = {5c 6c 6f 6d 6d 65 74 72 6b 6c 64 65 72 73 2e 68 74 6d } //1 \lommetrklders.htm
		$a_81_2 = {5c 75 6c 74 72 61 73 65 6c 65 63 74 2e 69 6e 69 } //1 \ultraselect.ini
		$a_81_3 = {5c 61 64 76 61 6e 63 65 5c 49 6e 73 6f 6c 76 65 6e 74 65 37 34 2e 6a 70 67 } //1 \advance\Insolvente74.jpg
		$a_81_4 = {5c 72 65 70 65 72 70 6c 65 78 2e 6a 70 67 } //1 \reperplex.jpg
		$a_81_5 = {5c 73 69 64 65 6c 65 73 73 5c 66 6f 72 6d 75 65 66 6c 6c 65 73 73 6b 61 62 65 72 6e 65 73 2e 74 78 74 } //1 \sideless\formuefllesskabernes.txt
		$a_81_6 = {5c 63 65 6e 73 75 73 73 65 73 2e 74 78 74 } //1 \censusses.txt
		$a_81_7 = {5c 73 61 72 61 62 61 6e 64 5c 55 64 74 61 6c 65 6c 73 65 6e 32 32 33 2e 6c 6e 6b } //1 \saraband\Udtalelsen223.lnk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}