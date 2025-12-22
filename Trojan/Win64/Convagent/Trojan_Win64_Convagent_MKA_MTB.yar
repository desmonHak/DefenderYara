
rule Trojan_Win64_Convagent_MKA_MTB{
	meta:
		description = "Trojan:Win64/Convagent.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 bc 01 00 00 00 4c 89 e1 48 8b 95 98 05 00 00 48 8b 9d b8 05 00 00 49 89 d8 e8 ?? ?? ?? ?? 48 89 9d 00 05 00 00 4c 89 a5 80 05 00 00 4c 89 a5 08 05 00 00 48 89 9d 10 05 00 00 48 89 f1 48 8b 95 68 05 } //15
		$a_01_1 = {4c 01 fb 48 89 9d e0 04 00 00 0f 10 85 00 05 00 00 0f 29 85 d0 04 00 00 48 8b 95 d0 03 00 00 48 8d 04 55 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}