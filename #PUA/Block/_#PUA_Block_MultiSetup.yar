
rule _#PUA_Block_MultiSetup{
	meta:
		description = "!#PUA:Block:MultiSetup,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_80_0 = {6f 70 65 72 61 73 65 74 75 70 2e 65 78 65 } //operasetup.exe  1
		$a_80_1 = {4d 53 65 74 75 70 2e 65 78 65 } //MSetup.exe  1
		$a_80_2 = {5c 42 6f 6f 5c 43 6f 64 65 5c 4f 66 66 65 72 67 61 74 65 5c 4d 75 6c 74 69 53 65 74 75 70 } //\Boo\Code\Offergate\MultiSetup  1
		$a_80_3 = {50 6c 61 79 47 61 6d 65 73 2e 70 72 6f } //PlayGames.pro  1
		$a_80_4 = {33 36 30 74 6f 74 61 6c 73 65 63 75 72 69 74 79 2e 63 6f 6d } //360totalsecurity.com  1
		$a_80_5 = {61 64 62 6c 6f 63 6b 66 61 73 74 2e 63 6f 6d } //adblockfast.com  1
		$a_80_6 = {75 73 65 64 4f 66 66 65 72 73 } //usedOffers  1
		$a_80_7 = {6f 66 66 65 72 73 } //offers  1
		$a_80_8 = {6f 66 66 65 72 4d 61 74 63 68 } //offerMatch  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=8
 
}
rule _#PUA_Block_MultiSetup_2{
	meta:
		description = "!#PUA:Block:MultiSetup,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 73 52 65 6a 65 63 74 69 6f 6e 44 69 61 6c 6f 67 4d 65 73 73 61 67 65 } //offersRejectionDialogMessage  1
		$a_80_1 = {6f 66 66 65 72 73 52 65 6a 65 63 74 69 6f 6e 44 69 61 6c 6f 67 54 69 74 6c 65 } //offersRejectionDialogTitle  1
		$a_80_2 = {68 76 72 4f 66 66 65 72 4e 65 78 74 } //hvrOfferNext  1
		$a_80_3 = {6d 73 67 53 63 72 65 65 6e 4f 66 66 65 72 44 65 73 63 72 69 70 74 69 6f 6e } //msgScreenOfferDescription  1
		$a_80_4 = {75 73 65 64 4f 66 66 65 72 73 } //usedOffers  1
		$a_80_5 = {41 76 61 73 74 20 46 72 65 65 20 41 6e 74 69 76 69 72 75 73 } //Avast Free Antivirus  1
		$a_80_6 = {6d 75 6c 74 69 73 65 74 75 70 5f 6c 6f 67 6f 2e 70 6e 67 } //multisetup_logo.png  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_MultiSetup_3{
	meta:
		description = "!#PUA:Block:MultiSetup,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 43 52 45 45 4e 5f 44 45 43 4c 49 4e 45 5f 4f 46 46 45 52 5f 41 46 54 45 52 5f 53 45 4c 45 43 54 45 44 5f 50 52 4f 47 52 41 4d } //SCREEN_DECLINE_OFFER_AFTER_SELECTED_PROGRAM  1
		$a_80_1 = {61 70 69 2f 65 78 65 63 75 74 65 6f 66 66 65 72 2f 62 75 6e 64 6c 65 5f 69 64 2f 2f 6a 73 6f 6e 2f 31 2f } //api/executeoffer/bundle_id//json/1/  1
		$a_80_2 = {6c 69 73 74 5f 6f 66 66 65 72 5f 74 65 73 74 2e 70 6e 67 } //list_offer_test.png  1
		$a_80_3 = {41 64 62 6c 6f 63 6b 20 46 61 73 74 } //Adblock Fast  1
		$a_80_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c 62 72 6f 77 73 65 72 2e 65 78 65 } //C:\Program files\Yandex\YandexBrowser\Application\browser.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_MultiSetup_4{
	meta:
		description = "!#PUA:Block:MultiSetup,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {75 73 65 64 4f 66 66 65 72 73 } //usedOffers  1
		$a_80_1 = {64 65 6e 69 65 64 4f 66 66 65 72 73 } //deniedOffers  1
		$a_80_2 = {62 75 6e 64 6c 65 49 64 } //bundleId  1
		$a_80_3 = {75 72 6c 44 6f 77 6e 6c 6f 61 64 } //urlDownload  1
		$a_80_4 = {73 69 6c 65 6e 74 50 61 72 61 6d 65 74 65 72 } //silentParameter  1
		$a_80_5 = {5c 6d 73 65 74 75 70 5c 6d 73 65 74 75 70 2e 65 78 65 } //\msetup\msetup.exe  1
		$a_80_6 = {79 61 6e 64 65 78 2e 72 75 2f 73 6f 66 74 2f 64 69 73 74 72 69 62 75 74 69 6f 6e 2f } //yandex.ru/soft/distribution/  1
		$a_80_7 = {53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 } //Software\Opera Software  1
		$a_80_8 = {53 4f 46 54 57 41 52 45 5c 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 5c 41 76 61 73 74 } //SOFTWARE\AVAST Software\Avast  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}
rule _#PUA_Block_MultiSetup_5{
	meta:
		description = "!#PUA:Block:MultiSetup,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {50 72 6f 67 72 61 6d 73 4c 69 73 74 4f 66 66 65 72 } //ProgramsListOffer  1
		$a_80_1 = {68 76 72 4f 66 66 65 72 4e 65 78 74 } //hvrOfferNext  1
		$a_80_2 = {6d 73 65 74 75 70 } //msetup  1
		$a_80_3 = {6d 73 67 53 63 72 65 65 6e 4f 66 66 65 72 44 65 73 63 72 69 70 74 69 6f 6e } //msgScreenOfferDescription  1
		$a_80_4 = {70 72 6f 67 72 61 6d 5f 66 6f 72 5f 63 61 74 61 6c 6f 67 5f 6f 66 66 65 72 2e 63 70 70 } //program_for_catalog_offer.cpp  1
		$a_80_5 = {59 41 42 52 4f 57 53 45 52 } //YABROWSER  1
		$a_80_6 = {63 6f 6d 70 6c 61 69 6e 74 5f 72 65 70 6f 72 74 69 6e 67 5f 77 69 6e 64 6f 77 2e 63 70 70 } //complaint_reporting_window.cpp  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=7
 
}