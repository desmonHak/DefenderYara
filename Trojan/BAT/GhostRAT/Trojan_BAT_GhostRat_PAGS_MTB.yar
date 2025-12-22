
rule Trojan_BAT_GhostRat_PAGS_MTB{
	meta:
		description = "Trojan:BAT/GhostRat.PAGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 20 53 74 65 61 6c 65 72 } //2 Telegram Stealer
		$a_01_1 = {53 74 65 61 6c 54 44 61 74 61 } //2 StealTData
		$a_01_2 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //1 CopyFromScreen
		$a_00_3 = {54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 44 00 61 00 74 00 61 00 } //1 Telegram Data
		$a_00_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 49 00 6e 00 66 00 6f 00 } //1 System Info
		$a_01_5 = {42 4f 54 5f 54 4f 4b 45 4e } //1 BOT_TOKEN
		$a_01_6 = {43 61 70 74 75 72 65 44 65 73 6b 74 6f 70 53 63 72 65 65 6e 73 68 6f 74 } //2 CaptureDesktopScreenshot
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=10
 
}