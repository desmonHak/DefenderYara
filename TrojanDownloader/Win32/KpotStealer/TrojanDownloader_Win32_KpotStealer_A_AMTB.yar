
rule TrojanDownloader_Win32_KpotStealer_A_AMTB{
	meta:
		description = "TrojanDownloader:Win32/KpotStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 74 72 79 6e 64 61 2e 78 79 7a 2f } //http://trynda.xyz/  3
		$a_80_1 = {68 74 74 70 3a 2f 2f 31 39 33 2e 31 33 35 2e 31 32 2e 31 30 37 2f 66 69 6c 65 31 2e 65 78 65 } //http://193.135.12.107/file1.exe  3
		$a_80_2 = {73 68 65 6c 6c 33 32 } //shell32  1
		$a_80_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //InternetReadFile  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}