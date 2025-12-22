
rule _#PUA_Block_OpenInstaller{
	meta:
		description = "!#PUA:Block:OpenInstaller,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 61 6e 63 65 6c 4f 66 66 65 72 54 68 72 65 61 64 73 } //CancelOfferThreads  1
		$a_80_1 = {50 61 67 65 4f 66 66 65 72 } //PageOffer  1
		$a_80_2 = {73 68 6f 77 6e 4f 66 66 65 72 73 } //shownOffers  1
		$a_80_3 = {70 72 65 70 61 72 65 64 4f 66 66 65 72 73 } //preparedOffers  1
		$a_80_4 = {49 73 4f 66 66 65 72 54 68 72 65 61 64 52 75 6e 6e 69 6e 67 } //IsOfferThreadRunning  1
		$a_80_5 = {64 69 73 61 62 6c 65 44 79 6e 61 6d 69 63 4f 66 66 65 72 73 } //disableDynamicOffers  1
		$a_80_6 = {65 72 72 2e 63 6c 6f 69 6e 73 2e 63 6f 6d } //err.cloins.com  1
		$a_80_7 = {73 74 2e 63 6c 6f 69 6e 73 2e 63 6f 6d } //st.cloins.com  1
		$a_80_8 = {61 66 74 65 72 64 61 77 6e 2e 63 6f 6d } //afterdawn.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}