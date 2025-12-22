
rule TrojanSpy_AndroidOS_SeedSnatcher_AMTB{
	meta:
		description = "TrojanSpy:AndroidOS/SeedSnatcher!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 32 64 65 63 78 64 38 73 79 77 37 6b 2e 74 6f 70 } //2 a2decxd8syw7k.top
		$a_01_1 = {66 61 6b 65 5f 64 65 78 2e 6a 61 72 } //1 fake_dex.jar
		$a_01_2 = {73 61 76 65 53 6d 73 } //1 saveSms
		$a_01_3 = {73 61 76 65 43 6f 6e 74 61 63 74 73 } //1 saveContacts
		$a_01_4 = {73 61 76 65 4d 6e 65 6d 6f 6e 69 63 73 } //1 saveMnemonics
		$a_01_5 = {73 61 76 65 43 61 6c 6c 4c 6f 67 } //1 saveCallLog
		$a_01_6 = {53 65 65 64 5f 50 68 72 61 73 65 5f 6f 72 5f 50 72 69 76 61 74 65 5f 4b 65 79 } //1 Seed_Phrase_or_Private_Key
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}