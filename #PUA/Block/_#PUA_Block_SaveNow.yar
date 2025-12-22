
rule _#PUA_Block_SaveNow{
	meta:
		description = "!#PUA:Block:SaveNow,SIGNATURE_TYPE_PEHSTR,05 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 68 65 6e 55 4f 66 66 65 72 73 } //1 WhenUOffers
		$a_01_1 = {73 61 76 65 6e 6f 77 2e 68 74 6d } //1 savenow.htm
		$a_01_2 = {73 61 76 65 6e 6f 77 2e 64 62 } //1 savenow.db
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 57 68 65 6e 55 5c 53 61 76 65 4e 6f 77 } //1 SOFTWARE\WhenU\SaveNow
		$a_01_4 = {73 61 76 65 6e 6f 77 75 70 64 61 74 65 2e 65 78 65 } //1 savenowupdate.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}