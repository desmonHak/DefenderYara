
rule Trojan_Win64_Vidar_AR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 02 0e 2c 00 40 09 00 00 1a } //3
		$a_01_1 = {50 0d 00 00 10 00 00 00 e0 04 00 } //2
		$a_01_2 = {60 0d 00 00 04 00 00 00 f0 04 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}