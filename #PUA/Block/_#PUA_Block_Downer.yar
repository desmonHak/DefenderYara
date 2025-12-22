
rule _#PUA_Block_Downer{
	meta:
		description = "!#PUA:Block:Downer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 6c 6f 61 64 65 72 2e 61 6c 64 74 6f 70 2e 63 6f 6d } //downloader.aldtop.com  2
		$a_80_1 = {42 43 6c 6f 73 65 4d 73 67 2e 78 6d 6c } //BCloseMsg.xml  1
		$a_80_2 = {55 49 44 6f 77 6e 65 72 } //UIDowner  1
		$a_80_3 = {55 49 44 6f 77 6e 6c 6f 61 64 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 55 49 44 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62 } //UIDownloader\bin\Release\UIDownloader.pdb  1
		$a_80_4 = {64 6f 77 6e 65 72 61 70 69 2e 63 6f 6d } //downerapi.com  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}
rule _#PUA_Block_Downer_2{
	meta:
		description = "!#PUA:Block:Downer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {55 49 44 6f 77 6e 6c 6f 61 64 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 73 65 74 75 70 5f 31 5f 32 33 37 31 34 38 2e 70 64 62 } //UIDownloader\bin\Release\setup_1_237148.pdb  1
		$a_80_1 = {64 6f 77 6e 6c 6f 61 64 65 72 2e 72 65 67 65 65 76 65 2e 63 6f 6d 2f 63 6c 69 65 6e 74 2f 64 65 62 75 67 } //downloader.regeeve.com/client/debug  1
		$a_80_2 = {61 70 69 2e 6e 61 73 79 65 6f 2e 63 6f 6d 2f 6c 6f 67 2f 63 6c 6f 73 65 } //api.nasyeo.com/log/close  1
		$a_80_3 = {66 6c 6d 67 72 2e 6e 65 74 2f 77 69 6e 5f 66 6c 5f 61 67 72 65 65 6d 65 6e 74 2e 68 74 6d 6c } //flmgr.net/win_fl_agreement.html  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Downer_3{
	meta:
		description = "!#PUA:Block:Downer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 [0-1f] 2e 00 64 00 6f 00 77 00 6e 00 65 00 72 00 61 00 70 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2f 00 64 00 65 00 62 00 75 00 67 00 } //2
		$a_02_1 = {68 74 74 70 [0-1f] 2e 64 6f 77 6e 65 72 61 70 69 2e 63 6f 6d 2f 63 6c 69 65 6e 74 2f 64 65 62 75 67 } //2
		$a_02_2 = {68 00 74 00 74 00 70 00 [0-1f] 2e 00 73 00 75 00 70 00 65 00 72 00 72 00 6c 00 2e 00 63 00 6e 00 2f 00 [0-0f] 2e 00 68 00 74 00 6d 00 6c 00 } //2
		$a_02_3 = {68 74 74 70 [0-1f] 2e 73 75 70 65 72 72 6c 2e 63 6e 2f [0-0f] 2e 68 74 6d 6c } //2
		$a_80_4 = {42 43 6c 6f 73 65 4d 73 67 2e 78 6d 6c } //BCloseMsg.xml  1
		$a_80_5 = {57 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c } //WSoftware\Classes\  1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}