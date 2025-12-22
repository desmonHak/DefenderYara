
rule Trojan_Win32_Zusy_GXT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 fe 0f 8d 45 d4 0f 47 c1 0f b6 0c 10 8b 45 bc 89 14 88 42 8b 4d d4 83 fa 40 7c } //5
		$a_01_1 = {69 44 54 48 4e 71 43 51 47 49 56 74 30 4b 46 51 55 68 39 4e 79 72 48 58 4b 47 51 37 6a 2f 61 61 } //5 iDTHNqCQGIVt0KFQUh9NyrHXKGQ7j/aa
		$a_01_2 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 api.telegram.org/bot
		$a_01_3 = {4d 79 53 75 70 65 72 53 65 63 72 65 74 4b 65 79 46 6f 72 41 45 53 32 35 36 49 73 47 6f 6f 64 21 } //1 MySuperSecretKeyForAES256IsGood!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}