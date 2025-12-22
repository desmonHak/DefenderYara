
rule _#PUA_Block_ICBundler{
	meta:
		description = "!#PUA:Block:ICBundler,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //OfferInstaller.exe  1
		$a_80_1 = {47 65 6e 65 72 69 63 53 65 74 75 70 2e 65 78 65 } //GenericSetup.exe  1
		$a_80_2 = {4f 66 66 65 72 4f 66 66 6c 69 6e 65 } //OfferOffline  1
		$a_80_3 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //profiles.ini  1
		$a_80_4 = {4f 70 65 72 61 } //Opera  1
		$a_80_5 = {59 61 6e 64 65 78 } //Yandex  1
		$a_80_6 = {47 65 74 42 72 6f 77 73 65 72 44 61 74 61 } //GetBrowserData  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_ICBundler_2{
	meta:
		description = "!#PUA:Block:ICBundler,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 65 72 76 69 63 65 42 4c 4c 2e 53 65 72 76 69 63 65 } //OfferServiceBLL.Service  1
		$a_80_1 = {67 65 74 5f 4f 66 66 65 72 49 6e 73 74 61 6c 6c 44 61 74 61 } //get_OfferInstallData  1
		$a_80_2 = {67 65 74 5f 4f 66 66 65 72 4d 65 74 61 64 61 74 61 } //get_OfferMetadata  1
		$a_80_3 = {47 65 74 49 6e 73 74 61 6e 74 42 75 6e 64 6c 65 4d 65 73 73 61 67 65 49 64 } //GetInstantBundleMessageId  1
		$a_80_4 = {67 65 74 5f 4f 66 66 65 72 49 64 } //get_OfferId  1
		$a_80_5 = {4f 66 66 65 72 41 63 63 65 70 74 65 64 } //OfferAccepted  1
		$a_80_6 = {3c 4f 66 66 65 72 43 68 65 63 6b 65 64 41 70 70 65 6e 64 54 6f 44 6f 77 6e 6c 6f 61 64 55 72 6c 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 } //<OfferCheckedAppendToDownloadUrl>k__BackingField  1
		$a_80_7 = {67 65 74 5f 4f 66 66 65 72 43 68 65 63 6b 65 64 43 6f 6d 6d 61 6e 64 4c 69 6e 65 } //get_OfferCheckedCommandLine  1
		$a_80_8 = {73 65 74 5f 41 63 63 65 70 74 42 75 74 74 6f 6e } //set_AcceptButton  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}