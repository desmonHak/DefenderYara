
rule Trojan_Win32_ValleyRat_NVA_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 43 47 61 6d 65 72 55 70 64 61 74 65 4d 61 69 6e } //2 TCGamerUpdateMain
		$a_81_1 = {5c 6a 69 6e 63 68 65 6e 67 2e 62 61 74 } //1 \jincheng.bat
		$a_81_2 = {5c 62 61 63 6b 75 70 2e 64 6c 6c } //1 \backup.dll
		$a_81_3 = {5c 6a 69 6e 63 68 65 6e 67 2e 70 69 64 } //1 \jincheng.pid
		$a_81_4 = {42 61 63 6b 75 70 44 4c 4c 50 61 74 68 } //1 BackupDLLPath
		$a_81_5 = {42 61 63 6b 75 70 50 72 6f 63 65 73 73 50 61 74 68 } //1 BackupProcessPath
		$a_81_6 = {67 6f 74 6f 20 43 68 65 63 6b 50 72 6f 63 65 73 73 } //1 goto CheckProcess
		$a_81_7 = {55 70 64 61 74 65 2e 64 6c 6c } //1 Update.dll
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}