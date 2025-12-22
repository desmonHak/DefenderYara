
rule Trojan_BAT_Zusy_KAE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 09 02 09 91 03 09 91 61 d2 9c 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d e5 } //10
		$a_01_1 = {6b 61 6e 5c 44 65 73 6b 74 6f 70 5c 64 65 6e 34 34 34 5c 64 65 6e 34 34 34 5c 6f 62 6a 5c 44 65 62 75 67 5c 64 65 6e 34 34 34 2e 70 64 62 } //20 kan\Desktop\den444\den444\obj\Debug\den444.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}