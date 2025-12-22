
rule _#PUA_Block_OpenCandy{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //1 api.opencandy.com
		$a_02_1 = {4f 43 50 52 44 [0-04] 4f 70 65 6e 43 61 6e 64 79 31 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule _#PUA_Block_OpenCandy_2{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //opencandy.com  2
		$a_80_1 = {4f 43 45 78 65 63 75 74 65 4f 66 66 65 72 } //OCExecuteOffer  1
		$a_80_2 = {4f 43 47 65 74 4f 66 66 65 72 54 79 70 65 } //OCGetOfferType  1
		$a_80_3 = {4f 43 53 65 74 75 70 48 6c 70 } //OCSetupHlp  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_OpenCandy_3{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //opencandy.com  2
		$a_80_1 = {4f 70 65 6e 43 61 6e 64 79 20 6f 66 66 65 72 73 } //OpenCandy offers  1
		$a_80_2 = {4f 43 4f 66 66 65 72 } //OCOffer  1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 4f 70 65 6e 43 61 6e 64 79 5c 73 64 6b } //SOFTWARE\OpenCandy\sdk  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_OpenCandy_4{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //opencandy.com  1
		$a_80_1 = {67 65 74 5f 6f 66 66 65 72 73 } //get_offers  1
		$a_80_2 = {4f 66 66 65 72 53 6b 69 70 70 65 64 } //OfferSkipped  1
		$a_80_3 = {63 69 72 63 75 6c 61 72 5f 6f 66 66 65 72 73 } //circular_offers  1
		$a_80_4 = {4f 43 53 65 74 75 70 48 6c 70 2e 64 6c 6c } //OCSetupHlp.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_OpenCandy_5{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //1 api.opencandy.com
		$a_00_1 = {4f 43 53 65 74 75 70 48 6c 70 2e 64 6c 6c } //1 OCSetupHlp.dll
		$a_80_2 = {4f 70 65 6e 43 61 6e 64 79 44 4c 4c } //OpenCandyDLL  1
		$a_80_3 = {4f 43 4f 66 66 65 72 } //OCOffer  1
		$a_80_4 = {67 65 74 5f 6f 66 66 65 72 73 } //get_offers  1
		$a_80_5 = {4f 66 66 65 72 53 6b 69 70 70 65 64 } //OfferSkipped  1
		$a_80_6 = {74 72 61 63 6b 5f 6f 66 66 65 72 5f 69 6e 73 74 61 6c 6c 5f 73 74 61 72 74 65 64 } //track_offer_install_started  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_OpenCandy_6{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {4f 43 53 65 74 75 70 48 6c 70 2e 64 6c 6c } //OCSetupHlp.dll  2
		$a_80_1 = {4f 70 65 6e 43 61 6e 64 79 20 49 6e 63 } //OpenCandy Inc  1
		$a_80_2 = {67 65 74 5f 6f 66 66 65 72 73 } //get_offers  1
		$a_80_3 = {4f 43 47 65 74 4f 66 66 65 72 53 74 61 74 65 } //OCGetOfferState  1
		$a_80_4 = {4f 43 53 65 74 4f 66 66 65 72 44 61 74 61 } //OCSetOfferData  1
		$a_80_5 = {4f 43 41 50 49 55 6e 69 74 54 65 73 74 } //OCAPIUnitTest  1
		$a_80_6 = {4f 70 65 6e 43 61 6e 64 79 5f 57 68 79 5f 49 73 5f 54 68 69 73 5f 48 65 72 65 } //OpenCandy_Why_Is_This_Here  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}
rule _#PUA_Block_OpenCandy_7{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {4f 70 65 6e 43 61 6e 64 79 } //OpenCandy  1
		$a_80_1 = {61 70 69 2e 6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //api.opencandy.com  1
		$a_80_2 = {4f 43 53 65 74 75 70 48 6c 70 2e 64 6c 6c } //OCSetupHlp.dll  1
		$a_80_3 = {73 74 61 74 73 2e 6f 70 65 6e 63 61 6e 64 79 2e 63 6f 6d } //stats.opencandy.com  1
		$a_80_4 = {41 44 44 4c 59 52 49 43 53 2e 4e 45 54 } //ADDLYRICS.NET  1
		$a_80_5 = {67 65 74 5f 6f 66 66 65 72 73 } //get_offers  1
		$a_80_6 = {6f 66 66 65 72 68 69 64 64 65 6e } //offerhidden  1
		$a_80_7 = {47 65 74 4f 66 66 65 72 54 79 70 65 } //GetOfferType  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule _#PUA_Block_OpenCandy_8{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_80_0 = {50 44 46 43 72 65 61 74 6f 72 2e 65 78 65 } //PDFCreator.exe  1
		$a_80_1 = {65 61 73 79 61 73 2e 63 6f 2e 7a 61 } //easyas.co.za  1
		$a_80_2 = {50 44 46 43 72 65 61 74 6f 72 5f 73 65 74 75 70 5f 73 71 6c 2e 65 78 65 } //PDFCreator_setup_sql.exe  1
		$a_80_3 = {43 3a 5c 65 5a 2d 41 7a 21 } //C:\eZ-Az!  1
		$a_80_4 = {50 44 46 49 6e 73 74 61 6c 6c 2e 65 78 65 } //PDFInstall.exe  1
		$a_80_5 = {70 64 66 73 65 74 75 70 2e 65 78 65 } //pdfsetup.exe  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=6
 
}
rule _#PUA_Block_OpenCandy_9{
	meta:
		description = "!#PUA:Block:OpenCandy,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {53 66 78 53 65 74 75 70 2e 65 78 65 } //SfxSetup.exe  1
		$a_80_1 = {4f 70 65 6e 43 61 6e 64 79 20 6f 66 66 65 72 } //OpenCandy offer  1
		$a_80_2 = {4f 43 53 65 74 75 70 48 6c 70 2e 64 6c 6c } //OCSetupHlp.dll  2
		$a_80_3 = {47 65 6e 75 69 6e 65 49 6e 74 65 6c 41 75 74 68 65 6e 74 69 63 41 4d 44 43 65 6e 74 61 75 72 48 61 75 6c 73 } //GenuineIntelAuthenticAMDCentaurHauls  1
		$a_00_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 6c 6d 79 61 70 70 73 2e 63 6f 6d } //1 http://www.allmyapps.com
		$a_00_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4f 00 70 00 65 00 6e 00 43 00 61 00 6e 00 64 00 79 00 5c 00 73 00 64 00 6b 00 } //1 SOFTWARE\OpenCandy\sdk
		$a_80_6 = {43 41 4e 44 59 52 58 } //CANDYRX  1
		$a_80_7 = {57 6e 55 6e 69 6e 73 74 2e 65 78 65 } //WnUninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=7
 
}