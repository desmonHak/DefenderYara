
rule _#PUA_Block_Rostpay{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  1
		$a_80_1 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_2 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_3 = {62 72 69 67 68 74 64 61 74 61 2e 63 6f 6d } //brightdata.com  1
		$a_80_4 = {5a 69 70 53 6f 66 74 2e 65 78 65 } //ZipSoft.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Rostpay_2{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  1
		$a_80_1 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_2 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_3 = {44 72 69 76 65 72 48 75 62 2e 65 78 65 } //DriverHub.exe  1
		$a_80_4 = {52 4f 53 54 50 41 59 20 4c 54 44 2e } //ROSTPAY LTD.  1
		$a_80_5 = {64 72 76 68 75 62 6f 66 66 65 72 } //drvhuboffer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Rostpay_3{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  2
		$a_80_1 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_2 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_3 = {59 61 6e 64 65 78 20 47 61 6d 65 73 } //Yandex Games  1
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 } //SOFTWARE\Opera Software  1
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 41 56 41 53 54 } //SOFTWARE\AVAST  1
		$a_80_6 = {2f 73 69 6c 65 6e 74 20 2f 72 75 6e } ///silent /run  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_Rostpay_4{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_80_0 = {52 4f 53 54 50 41 59 20 4c 54 44 } //ROSTPAY LTD  5
		$a_80_1 = {44 72 69 76 65 72 48 75 62 2e 65 78 65 } //DriverHub.exe  3
		$a_80_2 = {63 73 5f 61 66 66 3d 64 72 76 68 75 62 6f 66 66 65 72 } //cs_aff=drvhuboffer  2
		$a_80_3 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  1
		$a_80_4 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_5 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_6 = {4f 70 65 72 61 47 58 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //OperaGXDownloader.exe  1
		$a_80_7 = {41 76 61 73 74 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //AvastDownloader.exe  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*3+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=13
 
}
rule _#PUA_Block_Rostpay_5{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {70 72 2e 69 6e 73 74 61 6c 6c } //pr.install  1
		$a_80_1 = {70 72 2e 64 6f 77 6e 6c 6f 61 64 } //pr.download  1
		$a_80_2 = {70 72 2e 70 72 65 70 61 72 65 } //pr.prepare  1
		$a_80_3 = {70 72 2e 63 6f 6d 70 6c 65 74 65 } //pr.complete  1
		$a_80_4 = {50 72 6f 78 79 6d 61 44 61 74 61 } //ProxymaData  1
		$a_80_5 = {44 6c 6c 48 65 6c 70 65 72 49 6e 73 74 61 6c 6c 65 72 } //DllHelperInstaller  1
		$a_80_6 = {53 68 6f 77 4e 65 78 74 4f 66 66 65 72 } //ShowNextOffer  1
		$a_80_7 = {44 6c 6c 48 65 6c 70 65 72 2e 65 78 65 } //DllHelper.exe  1
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=8
 
}
rule _#PUA_Block_Rostpay_6{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  1
		$a_80_1 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_2 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_3 = {79 61 6e 64 65 78 2e 72 75 } //yandex.ru  1
		$a_80_4 = {41 76 61 73 74 50 65 72 73 69 73 74 65 6e 74 53 74 6f 72 61 67 65 } //AvastPersistentStorage  1
		$a_80_5 = {41 76 61 73 74 20 41 6e 74 69 76 69 72 75 73 } //Avast Antivirus  1
		$a_80_6 = {57 61 72 67 61 6d 69 6e 67 2e 6e 65 74 5c 47 61 6d 65 43 65 6e 74 65 72 5c 61 70 70 4d 61 69 6e } //Wargaming.net\GameCenter\appMain  1
		$a_80_7 = {44 72 69 76 65 72 48 75 62 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //DriverHubInstaller.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule _#PUA_Block_Rostpay_7{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 61 7a 2d 70 61 72 74 6e 65 72 73 2e 6e 65 74 2f 61 70 70 73 2f 7a 69 70 73 6f 66 74 2d 32 2f 6f 66 66 65 72 73 } //api.az-partners.net/apps/zipsoft-2/offers  1
		$a_80_1 = {61 70 69 2e 61 7a 2d 70 61 72 74 6e 65 72 73 2e 6e 65 74 2f 61 70 70 73 2f 7a 69 70 73 6f 66 74 2f 6f 66 66 65 72 73 } //api.az-partners.net/apps/zipsoft/offers  1
		$a_80_2 = {7a 69 70 73 6f 66 74 2e 72 75 2f 69 6e 66 6f 2f 6d 79 5f 73 6f 66 74 5f 61 75 74 6f 66 69 6c 6c } //zipsoft.ru/info/my_soft_autofill  1
		$a_80_3 = {4f 66 66 65 72 5f 69 6e 5f 73 6f 66 74 5f 61 63 63 65 70 74 65 64 } //Offer_in_soft_accepted  1
		$a_80_4 = {4f 66 66 65 72 5f 69 6e 5f 73 6f 66 74 5f 64 65 63 6c 69 6e 65 64 } //Offer_in_soft_declined  1
		$a_80_5 = {67 65 74 5f 4f 66 66 65 72 } //get_Offer  1
		$a_80_6 = {49 6e 73 74 61 6c 6c 4f 66 66 65 72 } //InstallOffer  1
		$a_80_7 = {50 72 65 4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 64 } //PreOfferInstalled  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule _#PUA_Block_Rostpay_8{
	meta:
		description = "!#PUA:Block:Rostpay,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 61 7a 2d 70 61 72 74 6e 65 72 73 2e 6e 65 74 } //api.az-partners.net  1
		$a_80_1 = {6f 66 66 65 72 3a 73 68 6f 77 6e } //offer:shown  1
		$a_80_2 = {6f 66 66 65 72 3a 61 63 63 65 70 74 65 64 } //offer:accepted  1
		$a_80_3 = {6f 66 66 65 72 3a 64 65 63 6c 69 6e 65 64 } //offer:declined  1
		$a_80_4 = {2f 73 69 6c 65 6e 74 20 2f 72 75 6e } ///silent /run  1
		$a_80_5 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //Yandex\YandexBrowser  1
		$a_80_6 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 41 76 61 73 74 20 41 6e 74 69 76 69 72 75 73 } //\Uninstall\Avast Antivirus  1
		$a_80_7 = {4f 70 65 72 61 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //OperaDownloader.exe  1
		$a_80_8 = {57 61 72 67 61 6d 69 6e 67 2e 6e 65 74 5c 47 61 6d 65 43 65 6e 74 65 72 5c 61 70 70 4d 61 69 6e } //Wargaming.net\GameCenter\appMain  1
		$a_80_9 = {44 72 69 76 65 72 48 75 62 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //DriverHubInstaller.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=9
 
}