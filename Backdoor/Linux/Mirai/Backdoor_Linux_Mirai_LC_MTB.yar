
rule Backdoor_Linux_Mirai_LC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 02 24 a0 e1 03 10 81 e1 ff 2c 02 e2 01 20 82 e1 ff 3c 02 e2 ff 08 02 e2 03 34 a0 e1 20 04 a0 e1 22 0c 80 e1 02 3c 83 e1 00 00 83 e1 0e f0 a0 e1 } //1
		$a_01_1 = {93 10 8d e2 01 20 a0 e3 05 00 a0 e1 ad ff ff eb 01 00 50 e3 04 00 a0 e3 8a ff ff 1b 93 30 dd e5 04 44 83 e1 7c 30 9f e5 03 00 54 e1 f3 ff ff 1a 0d 10 a0 e1 80 20 a0 e3 05 00 a0 e1 a1 ff ff eb 00 20 50 e2 0d 40 a0 e1 0d 10 a0 e1 07 00 a0 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}