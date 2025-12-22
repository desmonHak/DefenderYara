
rule Trojan_Win64_Bobik_SX_MTB{
	meta:
		description = "Trojan:Win64/Bobik.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 1f 99 f7 f9 0f af c5 8d 1c ?? ?? ?? ?? ?? 44 8d 73 ?? 4c 89 f1 } //15
		$a_01_1 = {48 8d 44 24 60 48 89 c6 f3 a5 48 89 44 24 28 49 8d 45 36 4c 89 e1 89 54 24 30 4c 89 fa 4c 89 ee 48 89 44 24 20 ff 15 } //10
		$a_01_2 = {2f 62 6f 74 25 73 2f 73 65 6e 64 50 68 6f 74 6f } //1 /bot%s/sendPhoto
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=26
 
}