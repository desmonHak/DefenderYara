
rule Trojan_AndroidOS_Thamera_J_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 10 11 45 07 00 0c 00 07 23 1f 03 dc 04 6e 10 c9 2a 03 00 22 04 38 08 12 05 70 30 01 2e 04 05 6e 40 b8 1d 43 11 0c 00 } //1
		$a_01_1 = {54 20 52 05 12 01 5b 01 8d 02 52 21 51 05 71 20 e5 0d 10 00 0e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}