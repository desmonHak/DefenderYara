
rule _#PUA_Block_DotBundler{
	meta:
		description = "!#PUA:Block:DotBundler,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 44 4b 41 50 49 49 6d 70 6c 3a 3a 73 65 74 4f 66 66 65 72 57 69 6e 64 6f 77 } //SDKAPIImpl::setOfferWindow  1
		$a_80_1 = {53 44 4b 41 50 49 49 6d 70 6c 3a 3a 73 68 6f 77 4f 66 66 65 72 } //SDKAPIImpl::showOffer  1
		$a_80_2 = {61 64 73 64 6b 20 20 73 68 6f 77 4f 66 66 65 72 } //adsdk  showOffer  1
		$a_80_3 = {64 6f 77 6e 6c 6f 61 64 5f 67 65 74 4f 66 66 65 72 } //download_getOffer  1
		$a_80_4 = {64 6f 77 6e 6c 6f 61 64 5f 61 63 63 65 70 74 4f 66 66 65 72 } //download_acceptOffer  1
		$a_80_5 = {44 6f 74 53 65 74 75 70 53 44 4b 2e 64 6c 6c } //DotSetupSDK.dll  1
		$a_80_6 = {4c 44 50 6c 61 79 65 72 20 49 6e 73 74 61 6c 6c 65 72 } //LDPlayer Installer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}