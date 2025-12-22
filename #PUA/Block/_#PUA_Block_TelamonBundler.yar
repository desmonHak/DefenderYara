
rule _#PUA_Block_TelamonBundler{
	meta:
		description = "!#PUA:Block:TelamonBundler,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 54 65 6c 61 6d 6f 6e } //Software\Telamon  1
		$a_80_1 = {4f 66 66 65 72 5f 59 61 6e 64 65 78 20 45 6e 64 } //Offer_Yandex End  1
		$a_80_2 = {4f 66 66 65 72 5f 59 61 6e 64 65 78 20 42 65 67 69 6e } //Offer_Yandex Begin  1
		$a_80_3 = {75 69 64 63 72 65 61 74 6f 72 2e 65 78 65 } //uidcreator.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_TelamonBundler_2{
	meta:
		description = "!#PUA:Block:TelamonBundler,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 74 74 2d 73 63 69 74 65 72 2d 69 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //1 \tt-sciter-installer.pdb
		$a_01_1 = {79 61 6e 64 65 78 5f 6f 66 66 65 72 } //1 yandex_offer
		$a_01_2 = {79 61 6e 64 65 78 5f 70 61 72 74 6e 65 72 5f 69 64 } //1 yandex_partner_id
		$a_01_3 = {69 6e 73 74 61 6c 6c 65 72 5f 79 61 6e 64 65 78 5f 6f 66 66 65 72 } //1 installer_yandex_offer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}