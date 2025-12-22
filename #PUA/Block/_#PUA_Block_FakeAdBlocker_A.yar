
rule _#PUA_Block_FakeAdBlocker_A{
	meta:
		description = "!#PUA:Block:FakeAdBlocker.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 65 72 73 69 73 74 65 64 49 6e 73 74 61 6c 6c 61 74 69 6f 6e } //1 PersistedInstallation
		$a_00_1 = {41 64 73 20 42 6c 6f 63 6b 65 72 } //1 Ads Blocker
		$a_00_2 = {61 6e 64 72 6f 69 64 43 6c 69 65 6e 74 49 6e 66 6f } //1 androidClientInfo
		$a_00_3 = {43 6c 65 61 6e 55 70 41 67 65 3d } //1 CleanUpAge=
		$a_03_4 = {69 6e 74 65 6e 73 [0-14] 49 4c 6f 61 64 41 70 6b } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}