
rule _#PUA_Block_YTDVideoDownload{
	meta:
		description = "!#PUA:Block:YTDVideoDownload,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {52 65 73 6f 75 72 63 65 73 5c 4f 66 66 65 72 50 61 67 65 2e 68 74 6d 6c } //Resources\OfferPage.html  1
		$a_80_1 = {42 75 6e 64 6c 65 43 6f 6e 66 69 67 } //BundleConfig  1
		$a_80_2 = {4f 66 66 65 72 53 65 72 76 69 63 65 42 4c 4c 2e 64 6c 6c } //OfferServiceBLL.dll  1
		$a_80_3 = {46 72 65 65 20 59 6f 75 54 75 62 65 20 44 6f 77 6e 6c 6f 61 64 65 72 } //Free YouTube Downloader  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_YTDVideoDownload_2{
	meta:
		description = "!#PUA:Block:YTDVideoDownload,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {45 61 73 79 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2c 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 6f 70 74 20 6f 75 74 20 66 72 6f 6d 20 61 64 64 69 74 69 6f 6e 61 6c 20 6f 66 66 65 72 73 } //Easy installation, automatically opt out from additional offers  1
		$a_80_1 = {43 4d 46 43 50 6f 70 75 70 4d 65 6e 75 42 61 72 } //CMFCPopupMenuBar  1
		$a_80_2 = {59 6f 75 74 75 62 65 44 6f 77 6e 6c 6f 61 64 65 72 } //YoutubeDownloader  1
		$a_80_3 = {54 6f 6f 6c 62 61 72 57 69 6e 64 6f 77 33 32 } //ToolbarWindow32  1
		$a_80_4 = {54 4f 4f 4c 42 41 52 5f 52 45 53 45 54 54 4f 4f 4c 42 41 52 } //TOOLBAR_RESETTOOLBAR  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_YTDVideoDownload_3{
	meta:
		description = "!#PUA:Block:YTDVideoDownload,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {45 61 73 79 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2c 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 6f 70 74 20 6f 75 74 20 66 72 6f 6d 20 61 64 64 69 74 69 6f 6e 61 6c 20 6f 66 66 65 72 73 } //Easy installation, automatically opt out from additional offers  1
		$a_80_1 = {42 43 47 54 4f 4f 4c 42 41 52 5f 50 4f 50 55 50 4d 45 4e 55 } //BCGTOOLBAR_POPUPMENU  1
		$a_80_2 = {42 43 47 54 4f 4f 4c 42 41 52 5f 52 45 53 45 54 54 4f 4f 4c 42 41 52 } //BCGTOOLBAR_RESETTOOLBAR  1
		$a_80_3 = {59 6f 75 74 75 62 65 20 4d 75 73 69 63 20 44 6f 77 6e 6c 6f 61 64 65 72 } //Youtube Music Downloader  1
		$a_80_4 = {59 6f 75 54 75 62 65 44 6f 77 6e 6c 6f 61 64 65 72 } //YouTubeDownloader  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}