
rule TrojanDownloader_Win32_Lazy_MK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 ffffff8c 00 07 00 00 "
		
	strings :
		$a_01_0 = {21 73 6c 6f 77 6c 6f 72 69 73 } //35 !slowloris
		$a_01_1 = {21 68 74 74 70 66 6c 6f 6f 64 } //30 !httpflood
		$a_01_2 = {21 44 4e 53 2d 51 55 45 52 59 2d 46 4c 4f 4f 44 } //25 !DNS-QUERY-FLOOD
		$a_01_3 = {21 68 74 74 70 62 79 70 61 73 73 } //20 !httpbypass
		$a_01_4 = {6b 61 72 72 75 6d 2e 74 78 74 } //15 karrum.txt
		$a_01_5 = {74 61 73 6b 5f 69 64 } //10 task_id
		$a_01_6 = {62 6f 74 5f 69 64 } //5 bot_id
	condition:
		((#a_01_0  & 1)*35+(#a_01_1  & 1)*30+(#a_01_2  & 1)*25+(#a_01_3  & 1)*20+(#a_01_4  & 1)*15+(#a_01_5  & 1)*10+(#a_01_6  & 1)*5) >=140
 
}