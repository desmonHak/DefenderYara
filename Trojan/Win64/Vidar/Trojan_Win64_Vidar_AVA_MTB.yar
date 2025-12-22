
rule Trojan_Win64_Vidar_AVA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 6b 79 37 2d 4b 64 61 68 57 64 61 61 6c } //5 bky7-KdahWdaal
		$a_01_1 = {57 45 6d 62 54 52 44 43 58 45 48 } //4 WEmbTRDCXEH
		$a_01_2 = {36 32 37 36 21 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 } //3 6276!SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
		$a_01_3 = {57 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 54 64 75 62 62 69 74 6f 68 73 } //2 WgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggTdubbitohs
		$a_01_4 = {51 52 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 57 61 6c 6c 65 74 20 52 75 6c 65 73 } //1 QRccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccWallet Rules
		$a_01_5 = {62 4f 4e 45 5f 42 5f 52 78 4e 59 5d 42 48 4e } //6 bONE_B_RxNY]BHN
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*6) >=21
 
}