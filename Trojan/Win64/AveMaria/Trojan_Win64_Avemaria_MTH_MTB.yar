
rule Trojan_Win64_Avemaria_MTH_MTB{
	meta:
		description = "Trojan:Win64/Avemaria.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 4c 8b d1 4c 8b 40 60 4d 8b 48 18 49 83 c1 20 49 8b 01 0f 1f 44 00 00 48 39 50 20 } //2
		$a_81_1 = {32 6a 6b 42 71 51 4d 76 48 39 6c 76 64 64 50 57 4a 65 59 71 74 43 2e 64 6c 6c } //1 2jkBqQMvH9lvddPWJeYqtC.dll
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}