
rule _#PUA_Block_FormatFactoryBundler{
	meta:
		description = "!#PUA:Block:FormatFactoryBundler,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {52 65 73 6f 75 72 63 65 73 5c 4f 66 66 65 72 50 61 67 65 2e 68 74 6d 6c } //Resources\OfferPage.html  1
		$a_80_1 = {42 75 6e 64 6c 65 43 6f 6e 66 69 67 } //BundleConfig  1
		$a_80_2 = {4f 66 66 65 72 53 65 72 76 69 63 65 42 4c 4c 2e 64 6c 6c } //OfferServiceBLL.dll  1
		$a_80_3 = {46 6f 72 6d 61 74 20 46 61 63 74 6f 72 79 } //Format Factory  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}