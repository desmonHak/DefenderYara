
rule Trojan_Win64_Mikey_KK_MTB{
	meta:
		description = "Trojan:Win64/Mikey.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 42 6f 78 47 75 65 73 74 2e 73 79 73 } //1 VBoxGuest.sys
		$a_01_1 = {76 6d 68 67 66 73 2e 73 79 73 } //2 vmhgfs.sys
		$a_01_2 = {57 44 41 47 55 74 69 6c 69 74 79 41 63 63 6f 75 6e 74 } //3 WDAGUtilityAccount
		$a_01_3 = {49 6d 61 67 65 44 6f 77 6e 6c 6f 61 64 65 72 } //4 ImageDownloader
		$a_03_4 = {73 74 61 72 74 20 43 3a 5c 55 73 65 72 73 5c [0-10] 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-10] 2e 6a 70 67 } //5
		$a_03_5 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 [0-15] 30 } //6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_03_4  & 1)*5+(#a_03_5  & 1)*6) >=21
 
}