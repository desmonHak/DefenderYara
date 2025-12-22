
rule _#PUA_Block_BitComet_BundleInstaller{
	meta:
		description = "!#PUA:Block:BitComet_BundleInstaller,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {47 45 54 4f 46 46 45 52 53 41 52 52 41 59 } //GETOFFERSARRAY  1
		$a_80_1 = {50 41 47 45 4f 46 46 45 52 41 43 54 49 56 41 54 45 } //PAGEOFFERACTIVATE  1
		$a_80_2 = {43 48 45 43 4b 4f 46 46 45 52 } //CHECKOFFER  1
		$a_80_3 = {49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //INSTALLOFFERS  1
		$a_80_4 = {5c 42 69 74 43 6f 6d 65 74 5c 42 69 74 43 6f 6d 65 74 2e 65 78 65 } //\BitComet\BitComet.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}