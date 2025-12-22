
rule Trojan_Win64_FsoRAT_YBG_MTB{
	meta:
		description = "Trojan:Win64/FsoRAT.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 0c 00 00 "
		
	strings :
		$a_01_0 = {53 76 63 55 70 64 61 74 65 5f } //10 SvcUpdate_
		$a_01_1 = {57 69 6e 64 6f 77 73 55 70 64 61 74 65 53 65 72 76 69 63 65 5f } //10 WindowsUpdateService_
		$a_01_2 = {73 76 63 68 6f 73 74 5f } //10 svchost_
		$a_01_3 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 } //10 schtasks /create
		$a_01_4 = {25 73 2f 62 6f 74 25 73 2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //10 %s/bot%s/sendDocument
		$a_01_5 = {2f 73 61 6c 75 64 6f } //10 /saludo
		$a_01_6 = {2f 73 63 72 65 65 6e 73 68 6f 74 } //10 /screenshot
		$a_01_7 = {2f 6b 65 79 6c 6f 67 20 3c 73 74 61 72 74 7c 73 74 6f 70 7c 64 75 6d 70 3e } //10 /keylog <start|stop|dump>
		$a_01_8 = {2f 65 78 66 69 6c 5f 67 65 74 20 3c 6e 6f 6d 62 72 65 5f 61 72 63 68 69 76 6f 3e 20 3c 72 75 74 61 3e } //10 /exfil_get <nombre_archivo> <ruta>
		$a_01_9 = {2f 63 6c 69 70 62 6f 61 72 64 } //10 /clipboard
		$a_01_10 = {2f 6c 69 73 74 5f 76 69 63 74 69 6d 73 } //10 /list_victims
		$a_03_11 = {80 74 24 62 ?? 45 33 c0 80 74 24 63 ?? 80 74 24 64 ?? 80 74 24 65 ?? 80 74 24 66 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_03_11  & 1)*1) >=111
 
}