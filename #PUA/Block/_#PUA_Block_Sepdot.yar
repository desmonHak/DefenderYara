
rule _#PUA_Block_Sepdot{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {61 54 75 62 65 } //aTube  2
		$a_80_1 = {6f 70 74 69 6f 6e 61 6c 50 61 67 65 } //optionalPage  1
		$a_80_2 = {44 6f 74 53 65 74 75 70 } //DotSetup  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}
rule _#PUA_Block_Sepdot_2{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 6f 62 72 65 70 72 6f 67 72 61 6d 79 } //dobreprogramy  2
		$a_80_1 = {6f 70 74 69 6f 6e 61 6c 50 61 67 65 } //optionalPage  1
		$a_80_2 = {44 6f 74 53 65 74 75 70 } //DotSetup  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}
rule _#PUA_Block_Sepdot_3{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 32 76 30 7a 65 74 67 75 36 68 6f 74 76 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //d2v0zetgu6hotv.cloudfront.net  2
		$a_80_1 = {62 75 69 6c 64 2f 69 6c 2f 76 36 2e 37 35 2e 35 30 2e 30 39 35 2e 35 37 } //build/il/v6.75.50.095.57  1
		$a_80_2 = {5c 50 6f 77 65 72 49 53 4f 2e 63 68 6d } //\PowerISO.chm  1
		$a_80_3 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //unknowndll.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Sepdot_4{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 6f 74 53 65 74 75 70 20 49 6e 73 74 61 6c 6c 65 72 } //1 DotSetup Installer
		$a_00_1 = {44 6f 74 53 65 74 75 70 53 44 4b } //1 DotSetupSDK
		$a_00_2 = {44 6f 74 53 65 74 75 70 2e 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e 50 61 63 6b 61 67 65 73 } //1 DotSetup.Installation.Packages
		$a_80_3 = {6f 70 65 72 61 2e 65 78 65 } //opera.exe  1
		$a_80_4 = {46 49 52 45 46 4f 58 2e 45 58 45 } //FIREFOX.EXE  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Sepdot_5{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 43 68 72 6f 6d 65 65 78 65 } //GetChromeexe  1
		$a_80_1 = {47 65 74 49 45 45 78 65 } //GetIEExe  1
		$a_80_2 = {47 65 74 45 64 67 65 45 78 65 } //GetEdgeExe  1
		$a_80_3 = {47 65 74 4f 70 65 72 61 45 58 45 } //GetOperaEXE  1
		$a_80_4 = {47 65 74 46 69 72 65 66 6f 78 45 78 65 } //GetFirefoxExe  1
		$a_80_5 = {42 61 69 78 61 6b 69 5f 53 65 74 75 70 2e 65 78 65 } //Baixaki_Setup.exe  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*2) >=7
 
}
rule _#PUA_Block_Sepdot_6{
	meta:
		description = "!#PUA:Block:Sepdot,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {43 6f 6f 6c 52 4f 4d 5f 53 65 74 75 70 2e 65 78 65 } //CoolROM_Setup.exe  1
		$a_80_1 = {44 6f 74 53 65 74 75 70 53 44 4b } //DotSetupSDK  1
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 55 52 4c } //DownloadURL  1
		$a_80_3 = {46 72 6d 4f 70 74 69 6f 6e 61 6c 50 61 67 65 } //FrmOptionalPage  1
		$a_80_4 = {41 43 43 45 50 54 } //ACCEPT  1
		$a_80_5 = {44 45 43 4c 49 4e 45 } //DECLINE  1
		$a_80_6 = {53 4b 49 50 20 41 4c 4c } //SKIP ALL  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}