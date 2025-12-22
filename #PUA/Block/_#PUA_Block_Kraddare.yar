
rule _#PUA_Block_Kraddare{
	meta:
		description = "!#PUA:Block:Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 62 73 61 6c 73 61 2e 63 6f 6d } //www.bsalsa.com  1
		$a_80_1 = {76 65 6c 6c 79 2e 63 6f 2e 6b 72 } //velly.co.kr  1
		$a_80_2 = {74 6f 6f 6c 62 61 72 } //toolbar  1
		$a_80_3 = {74 61 73 6b 62 61 72 } //taskbar  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Kraddare_2{
	meta:
		description = "!#PUA:Block:Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {75 74 69 6c 6d 6f 6e } //utilmon  1
		$a_80_1 = {61 75 74 6f 75 74 69 6c } //autoutil  1
		$a_80_2 = {75 74 69 6c 6d 61 6e 69 61 } //utilmania  1
		$a_02_3 = {75 00 74 00 69 00 6c 00 [0-04] 2e 00 63 00 6f 00 6d 00 } //1
		$a_02_4 = {75 74 69 6c [0-04] 2e 63 6f 6d } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}
rule _#PUA_Block_Kraddare_3{
	meta:
		description = "!#PUA:Block:Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 68 65 6c 6c 42 72 6f 77 73 65 72 } //ShellBrowser  1
		$a_80_1 = {6f 70 65 6e 2e 68 61 6e 74 6f 6f 6c 73 2e 63 6f 2e 6b 72 2f 76 32 2f 63 6b 2e 61 73 70 } //open.hantools.co.kr/v2/ck.asp  1
		$a_80_2 = {6d 6d 6e 6e 65 6f 2e 63 6f 6d } //mmnneo.com  1
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 31 67 72 61 6d } //Software\1gram  1
		$a_80_4 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //TaskbarCreated  1
		$a_80_5 = {43 48 52 4f 4d 45 2e 45 58 45 } //CHROME.EXE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Kraddare_4{
	meta:
		description = "!#PUA:Block:Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 65 66 61 75 6c 74 2e 63 6c 6f 75 64 77 65 62 2e 63 6f 2e 6b 72 } //default.cloudweb.co.kr  1
		$a_80_1 = {68 74 74 70 3a 2f 2f 7b 7b 43 4f 4e 46 49 47 5f 44 4f 4d 41 49 4e 7d 7d 2f 63 6c 6f 75 64 5f 70 61 74 63 68 2e 70 68 70 } //http://{{CONFIG_DOMAIN}}/cloud_patch.php  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 43 6c 6f 75 64 2d 57 65 62 } //Software\Cloud-Web  1
		$a_80_3 = {50 52 4f 47 52 41 4d 46 49 4c 45 53 25 5c 43 6c 6f 75 64 2d 57 65 62 5c 43 6c 6f 75 64 2d 57 65 62 5f 72 75 6e 2e 65 78 65 } //PROGRAMFILES%\Cloud-Web\Cloud-Web_run.exe  1
		$a_80_4 = {63 6c 6f 75 64 5f 72 65 70 6f 72 74 2e 70 68 70 } //cloud_report.php  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule _#PUA_Block_Kraddare_5{
	meta:
		description = "!#PUA:Block:Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {31 31 73 74 2e 63 6f 2e 6b 72 } //11st.co.kr  1
		$a_80_1 = {67 6d 61 72 6b 65 74 2e 63 6f 2e 6b 72 } //gmarket.co.kr  1
		$a_80_2 = {61 75 63 74 69 6f 6e 2e 63 6f 2e 6b 72 } //auction.co.kr  1
		$a_80_3 = {69 6e 74 65 72 70 61 72 6b 2e 63 6f 2e 6b 72 } //interpark.co.kr  1
		$a_80_4 = {63 6c 2e 6e 63 63 6c 69 63 6b 2e 63 6f 2e 6b 72 } //cl.ncclick.co.kr  1
		$a_80_5 = {62 61 72 6f 67 61 67 79 2e 63 6f 2e 6b 72 2f 73 69 64 65 62 61 72 2f 73 68 6f 70 5f 6b 65 79 77 6f 72 64 2e 61 73 70 3f 73 77 6f 72 64 3d } //barogagy.co.kr/sidebar/shop_keyword.asp?sword=  1
		$a_80_6 = {57 42 50 61 74 63 68 6f 70 65 6e 2e 65 78 65 } //WBPatchopen.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}