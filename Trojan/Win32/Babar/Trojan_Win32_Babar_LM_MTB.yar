
rule Trojan_Win32_Babar_LM_MTB{
	meta:
		description = "Trojan:Win32/Babar.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 56 00 00 00 2b 95 5c ff ff ff 89 55 f0 b8 61 00 00 00 2b 45 d8 0b 85 64 ff ff ff 89 85 64 ff ff ff 8b 8d 5c ff ff ff 03 4d d8 03 8d 3c ff ff ff 0f b7 95 40 ff ff ff 2b ca } //10
		$a_01_1 = {8b 8d 64 ff ff ff 83 c1 56 89 8d 5c ff ff ff 0f b7 55 dc 03 55 d8 33 55 d8 33 95 5c ff ff ff 0f b7 45 a4 33 d0 88 55 f7 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}