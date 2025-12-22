
rule Trojan_Win64_Xmrig_NG_MTB{
	meta:
		description = "Trojan:Win64/Xmrig.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c7 40 18 07 00 00 00 4c 8d 44 24 30 48 8d 15 da e5 02 00 48 8d 8c 24 90 00 00 00 e8 7d af ff ff 48 8d 8c 24 90 00 00 00 48 83 bc 24 a8 00 00 00 07 48 0f 47 8c 24 90 00 00 00 45 33 c0 33 d2 } //2
		$a_01_1 = {4c 89 70 10 48 c7 40 18 07 00 00 00 81 ce 00 00 00 80 4c 8d 85 f8 04 00 00 48 8d 15 d6 0c 03 00 48 8d 8d 30 01 00 00 e8 5a d6 ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}