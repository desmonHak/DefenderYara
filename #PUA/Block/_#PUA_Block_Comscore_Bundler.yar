
rule _#PUA_Block_Comscore_Bundler{
	meta:
		description = "!#PUA:Block:Comscore_Bundler,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 6b 5f 73 65 74 75 70 2e 65 78 65 } //rk_setup.exe  1
		$a_80_1 = {66 72 65 65 2d 61 75 74 6f 2d 63 6c 69 63 6b 65 72 2e 63 6f 6d } //free-auto-clicker.com  1
		$a_80_2 = {73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //securestudies.com  1
		$a_80_3 = {46 72 65 65 41 75 74 6f 43 6c 69 63 6b 65 72 } //FreeAutoClicker  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Comscore_Bundler_2{
	meta:
		description = "!#PUA:Block:Comscore_Bundler,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 67 77 61 72 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 2f } //pgware.com/downloads/  1
		$a_80_1 = {46 52 45 45 52 4b 42 41 4e 4e 45 52 } //FREERKBANNER  1
		$a_80_2 = {52 55 4e 52 4b 56 45 52 49 46 59 } //RUNRKVERIFY  1
		$a_80_3 = {72 6b 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //rkinstaller.exe  1
		$a_80_4 = {5c 50 47 57 41 52 45 5c 54 68 72 6f 74 74 6c 65 } //\PGWARE\Throttle  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Comscore_Bundler_3{
	meta:
		description = "!#PUA:Block:Comscore_Bundler,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {50 72 65 6d 69 65 72 4f 70 69 6e 69 6f 6e } //PremierOpinion  1
		$a_80_1 = {69 6e 73 74 61 6c 6c 4f 66 66 65 72 } //installOffer  1
		$a_80_2 = {43 6f 6e 74 65 6e 74 49 33 2e 65 78 65 } //ContentI3.exe  1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 49 6e 73 74 61 6c 6c 55 6e 69 6f 6e } //SOFTWARE\InstallUnion  1
		$a_80_4 = {64 6c 73 66 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //dlsft.com/download.php  1
		$a_80_5 = {70 6f 73 74 2e 73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //post.securestudies.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}