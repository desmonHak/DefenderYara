
rule Trojan_Win64_Babar_LMA_MTB{
	meta:
		description = "Trojan:Win64/Babar.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ec 81 ec e8 00 00 00 c6 85 3f ff ff ff 31 c6 85 4b ff ff ff 2e c7 85 4c ff ff ff 1d 00 00 00 c7 85 30 ff ff ff 2c 00 00 00 c7 45 f0 2f 00 00 00 c7 85 78 ff ff ff 2f 00 00 00 0f b7 85 28 ff ff ff 0f b6 8d 72 ff ff ff 03 45 b8 03 c8 33 8d 40 ff ff ff } //10
		$a_01_1 = {8b 4d 80 83 c1 59 2b 4d c8 03 8d 24 ff ff ff 03 8d 38 ff ff ff 88 8d 5f ff ff ff 8b 55 80 83 c2 1f 0f b7 85 58 ff ff ff 8b 8d 64 ff ff ff 2b c8 0b d1 66 89 95 58 ff ff ff } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}