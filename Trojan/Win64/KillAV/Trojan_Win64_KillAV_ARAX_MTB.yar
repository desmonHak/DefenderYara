
rule Trojan_Win64_KillAV_ARAX_MTB{
	meta:
		description = "Trojan:Win64/KillAV.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 4e 53 65 63 53 6f 66 74 42 59 4f 56 44 2e 70 64 62 } //3 \NSecSoftBYOVD.pdb
		$a_01_1 = {55 6e 6c 6f 61 64 20 44 72 69 76 65 72 20 46 61 69 6c 65 64 2c 20 59 6f 75 20 6d 61 79 20 6e 65 65 64 20 74 6f 20 75 6e 6c 6f 61 64 20 64 72 69 76 65 72 20 6d 61 6e 75 61 6c 6c 79 } //2 Unload Driver Failed, You may need to unload driver manually
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}