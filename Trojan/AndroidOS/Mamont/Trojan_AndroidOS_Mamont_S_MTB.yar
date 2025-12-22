
rule Trojan_AndroidOS_Mamont_S_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 43 61 6c 6c 4c 6f 67 45 78 70 6f 72 74 65 72 } //1 BotCallLogExporter
		$a_01_1 = {42 6f 74 53 6d 73 45 78 70 6f 72 74 65 72 } //1 BotSmsExporter
		$a_01_2 = {65 78 70 6f 72 74 43 61 6c 6c 4c 6f 67 73 41 6e 64 55 70 6c 6f 61 64 } //1 exportCallLogsAndUpload
		$a_01_3 = {65 78 70 6f 72 74 53 6d 73 41 6e 64 55 70 6c 6f 61 64 } //1 exportSmsAndUpload
		$a_01_4 = {67 65 74 5f 62 6f 74 5f 63 6f 6d 6d 61 6e 64 73 2e 70 68 70 3f 74 61 67 3d } //1 get_bot_commands.php?tag=
		$a_01_5 = {42 6f 74 48 65 61 72 74 62 65 61 74 53 65 72 76 69 63 65 } //1 BotHeartbeatService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}