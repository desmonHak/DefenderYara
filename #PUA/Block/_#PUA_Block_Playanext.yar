
rule _#PUA_Block_Playanext{
	meta:
		description = "!#PUA:Block:Playanext,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {50 6c 61 79 61 4e 65 78 74 4f 66 66 65 72 56 69 65 77 2e 63 70 70 } //PlayaNextOfferView.cpp  2
		$a_80_1 = {70 6c 61 79 61 2d 6e 65 78 74 2d 6f 66 66 65 72 } //playa-next-offer  1
		$a_80_2 = {6f 70 74 69 6f 6e 61 6c 6f 66 66 65 72 } //optionaloffer  1
		$a_80_3 = {50 44 46 5f 53 75 69 74 65 } //PDF_Suite  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Playanext_2{
	meta:
		description = "!#PUA:Block:Playanext,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {75 70 63 6c 69 63 6b 2e 63 6f 6d } //upclick.com  2
		$a_80_1 = {50 6c 61 79 61 53 44 4b 20 4c 6f 61 64 4f 66 66 65 72 73 } //PlayaSDK LoadOffers  1
		$a_80_2 = {70 6c 61 79 61 2d 6e 65 78 74 2d 6f 66 66 65 72 2e 68 74 6d } //playa-next-offer.htm  1
		$a_80_3 = {70 64 66 61 72 63 68 69 74 65 63 74 } //pdfarchitect  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Playanext_3{
	meta:
		description = "!#PUA:Block:Playanext,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {50 6c 61 79 61 4e 65 78 74 } //PlayaNext  2
		$a_80_1 = {50 44 46 53 75 69 74 65 32 30 32 31 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //PDFSuite2021Installer.pdb  1
		$a_80_2 = {6f 70 74 69 6f 6e 61 6c 2d 6f 66 66 65 72 2d 63 6f 6e 73 65 6e 74 } //optional-offer-consent  1
		$a_80_3 = {6f 70 74 69 6f 6e 61 6c 6f 66 66 65 72 } //optionaloffer  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Playanext_4{
	meta:
		description = "!#PUA:Block:Playanext,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {50 6c 61 79 61 53 44 4b 2e 64 6c 6c } //PlayaSDK.dll  1
		$a_80_1 = {50 6c 61 79 61 50 61 72 74 6e 65 72 49 64 } //PlayaPartnerId  1
		$a_80_2 = {50 6c 61 79 61 53 44 4b 20 63 61 6c 6c 20 50 72 65 73 65 6e 74 4f 66 66 65 72 } //PlayaSDK call PresentOffer  1
		$a_80_3 = {50 6c 61 79 61 53 44 4b 20 63 61 6c 6c 20 41 63 63 65 70 74 4f 66 66 65 72 } //PlayaSDK call AcceptOffer  1
		$a_80_4 = {6f 70 74 69 6f 6e 61 6c 6f 66 66 65 72 } //optionaloffer  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}