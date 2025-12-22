
rule Trojan_Win32_Guloader_RR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_81_1 = {49 6e 69 74 69 61 74 65 53 68 75 74 64 6f 77 6e 57 } //1 InitiateShutdownW
		$a_00_2 = {46 00 72 00 65 00 6e 00 61 00 74 00 61 00 65 00 20 00 42 00 69 00 6f 00 65 00 6e 00 65 00 72 00 67 00 69 00 20 00 52 00 65 00 63 00 68 00 61 00 62 00 69 00 74 00 69 00 73 00 6d 00 } //2 Frenatae Bioenergi Rechabitism
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*2+(#a_81_3  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 72 69 7a 65 5c 41 75 74 6f 6d 61 74 63 61 66 65 32 30 39 } //1 posterize\Automatcafe209
		$a_01_1 = {68 75 67 75 65 6e 6f 74 69 73 6d 5c 70 69 70 61 67 65 73 5c 6d 75 6c 69 67 67 6f 65 72 } //1 huguenotism\pipages\muliggoer
		$a_01_2 = {5c 6e 61 70 6f 6c 65 6f 6e 73 68 61 74 74 65 73 2e 67 69 66 } //1 \napoleonshattes.gif
		$a_01_3 = {72 75 6e 64 69 6e 67 65 72 73 5c 73 6f 6c 69 66 6c 75 63 74 69 6f 6e 61 6c 5c 54 61 75 74 6f 6c 6f 67 69 7a 65 72 } //1 rundingers\solifluctional\Tautologizer
		$a_01_4 = {4b 75 6e 73 74 75 64 73 74 69 6c 6c 69 6e 67 73 2e 54 72 69 } //1 Kunstudstillings.Tri
		$a_01_5 = {4d 65 6c 6c 65 6d 72 75 6d 73 74 61 6e 67 65 6e 74 65 72 6e 65 73 2e 63 68 72 } //1 Mellemrumstangenternes.chr
		$a_01_6 = {5c 52 65 6d 61 69 6e 65 73 5c 45 67 61 6c 65 5c 53 70 65 63 69 61 6c 76 73 6b 65 5c 46 72 69 61 62 6c 65 } //1 \Remaines\Egale\Specialvske\Friable
		$a_01_7 = {5c 52 65 6d 61 69 6e 65 73 5c 4b 75 6e 73 74 75 64 73 74 69 6c 6c 69 6e 67 73 2e 54 72 69 } //1 \Remaines\Kunstudstillings.Tri
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Guloader_RR_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 70 6f 6c 79 61 6e 64 72 69 6f 75 73 2e 64 6c 6c } //1 \polyandrious.dll
		$a_01_1 = {6c 65 64 65 6c 73 65 73 6d 73 73 69 67 65 73 5c 71 75 69 6e 61 72 79 5c 70 6f 6e 63 68 6f 65 72 73 } //1 ledelsesmssiges\quinary\ponchoers
		$a_01_2 = {63 79 6b 65 6c 68 61 6e 64 6c 65 72 6e 65 73 } //1 cykelhandlernes
		$a_01_3 = {5c 70 61 6e 74 68 65 69 73 74 5c 66 65 6d 6f 67 74 79 76 65 61 61 72 73 6a 75 62 69 6c 75 6d 73 2e 69 6e 69 } //1 \pantheist\femogtyveaarsjubilums.ini
		$a_01_4 = {37 5c 61 61 62 65 6e 62 61 72 65 6c 73 65 6e 5c 73 61 6d 6c 65 6c 69 6e 73 65 72 6e 65 2e 67 69 66 } //1 7\aabenbarelsen\samlelinserne.gif
		$a_01_5 = {53 61 6e 6b 74 69 6f 6e 65 6e 5c 64 72 61 6d 61 74 75 72 67 65 72 73 } //1 Sanktionen\dramaturgers
		$a_01_6 = {63 3a 5c 4b 61 72 67 6f 65 6e 73 5c 6e 6f 72 74 68 6c 61 6e 64 5c 6d 65 6e 69 6e 67 73 6b 6f 72 72 65 6b 74 75 72 65 72 6e 65 73 2e 69 6e 69 } //1 c:\Kargoens\northland\meningskorrekturernes.ini
		$a_01_7 = {46 65 6d 6f 67 74 79 76 65 72 65 } //1 Femogtyvere
		$a_01_8 = {5c 6f 76 65 72 62 6c 69 6b 6b 65 6e 65 2e 74 78 74 } //1 \overblikkene.txt
		$a_01_9 = {54 79 6c 73 6b 6a 6f 6c 65 72 6e 65 2e 53 63 6c } //1 Tylskjolerne.Scl
		$a_01_10 = {5c 52 65 6d 6f 6e 73 74 72 61 6e 74 32 33 30 5c 6b 72 69 67 73 66 72 65 6c 73 65 72 6e 65 73 2e 65 78 65 } //1 \Remonstrant230\krigsfrelsernes.exe
		$a_01_11 = {65 6e 65 76 72 65 6c 73 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 74 6f 74 61 6c 73 79 73 74 65 6d 65 72 6e 65 73 5c 69 6d 6d 61 74 72 69 6b 75 6c 61 74 69 6f 6e 65 72 73 } //1 enevrelse\Uninstall\totalsystemernes\immatrikulationers
		$a_01_12 = {73 70 69 6c 6c 65 6b 6f 72 74 65 6e 65 73 5c 75 6e 68 75 6d 6f 72 6f 75 73 6e 65 73 73 5c 73 79 73 74 65 6d 75 64 76 69 6b 6c 69 6e 67 65 6e } //1 spillekortenes\unhumorousness\systemudviklingen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule Trojan_Win32_Guloader_RR_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 00 6e 00 74 00 65 00 72 00 6c 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 74 00 72 00 69 00 6d 00 65 00 74 00 68 00 79 00 6c 00 67 00 6c 00 79 00 63 00 69 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //1 interlucation trimethylglycine.exe
		$a_01_1 = {61 00 6e 00 6e 00 75 00 61 00 6c 00 73 00 20 00 75 00 64 00 6e 00 79 00 74 00 74 00 65 00 6c 00 69 00 67 00 74 00 20 00 67 00 61 00 72 00 61 00 6e 00 74 00 69 00 68 00 65 00 6e 00 73 00 74 00 74 00 65 00 6c 00 73 00 65 00 72 00 6e 00 65 00 } //1 annuals udnytteligt garantihensttelserne
		$a_01_2 = {61 00 6d 00 61 00 74 00 72 00 6f 00 72 00 6b 00 65 00 73 00 74 00 65 00 72 00 73 00 20 00 6f 00 75 00 74 00 72 00 61 00 6e 00 6b 00 } //1 amatrorkesters outrank
		$a_01_3 = {70 00 6a 00 75 00 73 00 6b 00 65 00 73 00 } //1 pjuskes
		$a_01_4 = {74 00 69 00 70 00 74 00 6f 00 70 00 70 00 69 00 73 00 68 00 } //1 tiptoppish
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 61 00 6b 00 74 00 75 00 72 00 61 00 64 00 61 00 74 00 6f 00 65 00 6e 00 20 00 75 00 6e 00 62 00 69 00 67 00 67 00 65 00 64 00 20 00 6d 00 61 00 6e 00 69 00 63 00 68 00 61 00 65 00 61 00 6e 00 69 00 7a 00 65 00 } //1 fakturadatoen unbigged manichaeanize
		$a_01_1 = {61 00 66 00 74 00 72 00 75 00 6b 00 6e 00 65 00 73 00 20 00 75 00 6e 00 66 00 65 00 61 00 74 00 68 00 65 00 72 00 20 00 72 00 65 00 73 00 75 00 6c 00 74 00 65 00 72 00 65 00 6e 00 64 00 65 00 73 00 } //1 aftruknes unfeather resulterendes
		$a_01_2 = {62 00 6c 00 74 00 65 00 6b 00 72 00 65 00 74 00 6a 00 65 00 72 00 6e 00 65 00 20 00 70 00 61 00 72 00 73 00 69 00 6d 00 6f 00 6e 00 79 00 2e 00 65 00 78 00 65 00 } //1 bltekretjerne parsimony.exe
		$a_01_3 = {62 00 65 00 73 00 6b 00 61 00 64 00 69 00 67 00 65 00 6c 00 73 00 65 00 72 00 } //1 beskadigelser
		$a_01_4 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 4a 00 6f 00 68 00 6e 00 44 00 6f 00 65 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 6c 00 69 00 6b 00 65 00 } //1 C:\Documents and Settings\JohnDoe\machinelike
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_6{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 00 69 00 67 00 61 00 6e 00 74 00 69 00 73 00 6b 00 2e 00 74 00 78 00 74 00 } //1 Gigantisk.txt
		$a_01_1 = {5c 00 53 00 75 00 62 00 72 00 61 00 64 00 69 00 63 00 6e 00 65 00 73 00 73 00 31 00 33 00 35 00 } //1 \Subradicness135
		$a_01_2 = {6d 00 6f 00 6c 00 6c 00 79 00 68 00 61 00 77 00 6b 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 62 00 61 00 72 00 62 00 65 00 72 00 65 00 5c 00 4f 00 72 00 69 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 6c 00 79 00 } //1 mollyhawk\Uninstall\barbere\Orientationally
		$a_01_3 = {5c 00 4c 00 65 00 6d 00 6d 00 65 00 73 00 36 00 37 00 5c 00 52 00 65 00 69 00 6d 00 70 00 6f 00 72 00 74 00 65 00 72 00 6e 00 65 00 2e 00 6a 00 70 00 67 00 } //1 \Lemmes67\Reimporterne.jpg
		$a_01_4 = {5c 00 75 00 64 00 68 00 75 00 67 00 67 00 65 00 6e 00 64 00 65 00 73 00 5c 00 55 00 64 00 62 00 72 00 65 00 6e 00 64 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 \udhuggendes\Udbrendes.exe
		$a_01_5 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 79 00 6f 00 67 00 69 00 73 00 5c 00 61 00 70 00 6f 00 74 00 65 00 6b 00 73 00 61 00 73 00 73 00 69 00 73 00 74 00 65 00 6e 00 74 00 65 00 72 00 6e 00 65 00 5c 00 46 00 61 00 6e 00 74 00 61 00 73 00 69 00 61 00 2e 00 6d 00 61 00 6c 00 } //1 C:\TEMP\yogis\apoteksassistenterne\Fantasia.mal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}