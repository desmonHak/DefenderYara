
rule Trojan_BAT_AirStalk_A_AMTB{
	meta:
		description = "Trojan:BAT/AirStalk.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 63 72 65 65 6e 73 68 6f 74 } //1 Screenshot
		$a_81_1 = {61 70 69 2f 6d 61 6d 2f 62 6c 6f 62 73 2f 75 70 6c 6f 61 64 62 6c 6f 62 } //1 api/mam/blobs/uploadblob
		$a_81_2 = {4b 69 6c 6c 69 6e 67 20 6f 6c 64 20 43 68 72 6f 6d 65 } //1 Killing old Chrome
		$a_81_3 = {42 6f 6f 6b 6d 61 72 6b 73 5f 74 6d 70 2e 74 78 74 } //1 Bookmarks_tmp.txt
		$a_81_4 = {41 69 72 57 61 74 63 68 44 65 62 75 67 5f 4c 6f 67 5f 74 6d 70 2e 74 78 74 } //1 AirWatchDebug_Log_tmp.txt
		$a_81_5 = {57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 50 72 6f 64 75 63 74 } //1 Win32_ComputerSystemProduct
		$a_81_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 75 6d 70 65 64 20 63 6f 6f 6b 69 65 73 } //1 Successfully dumped cookies
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}