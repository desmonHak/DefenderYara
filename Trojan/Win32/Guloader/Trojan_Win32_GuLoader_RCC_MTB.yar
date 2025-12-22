
rule Trojan_Win32_GuLoader_RCC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 79 72 69 61 6c 69 74 72 65 5c 66 6f 72 73 76 65 6e 73 6b 65 6e 64 65 73 5c 66 61 6c 73 69 74 69 65 73 } //1 myrialitre\forsvenskendes\falsities
		$a_81_1 = {25 6b 6f 6d 74 65 73 73 65 72 6e 65 73 25 5c 4f 76 65 72 66 61 69 6e 74 6c 79 5c 6d 6f 75 74 68 70 69 65 63 65 } //1 %komtessernes%\Overfaintly\mouthpiece
		$a_81_2 = {73 6b 72 69 76 65 74 69 6c 6c 61 64 65 6c 73 65 72 6e 65 } //1 skrivetilladelserne
		$a_81_3 = {66 6f 72 65 6e 65 6e 64 65 73 20 63 6f 6e 71 75 65 72 20 6c 79 73 68 61 61 72 65 74 } //1 forenendes conquer lyshaaret
		$a_81_4 = {6e 61 76 69 67 65 72 65 64 65 20 70 65 72 69 76 65 6e 6f 75 73 } //1 navigerede perivenous
		$a_81_5 = {62 69 67 61 6d 69 73 74 73 20 6c 6f 67 6f 6d 61 6e 63 79 2e 65 78 65 } //1 bigamists logomancy.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}