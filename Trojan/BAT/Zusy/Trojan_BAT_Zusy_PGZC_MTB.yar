
rule Trojan_BAT_Zusy_PGZC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PGZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6a 71 4b 4d 71 68 49 50 70 79 55 67 74 44 64 6e 41 5a 64 64 70 63 4f 43 50 66 } //jqKMqhIPpyUgtDdnAZddpcOCPf  1
		$a_80_1 = {61 50 75 4a 4c 66 55 6d 62 51 4f 66 59 62 4f 77 44 4c 59 64 77 61 46 43 51 45 } //aPuJLfUmbQOfYbOwDLYdwaFCQE  1
		$a_80_2 = {63 61 53 6e 72 71 4c 66 4a 52 47 6a 41 54 72 59 6e 53 6d 48 50 4f 50 43 49 52 } //caSnrqLfJRGjATrYnSmHPOPCIR  1
		$a_80_3 = {4e 4d 61 62 79 6e 64 62 76 67 76 44 77 67 4b 69 6a 71 4f 54 4c 76 69 49 66 7a } //NMabyndbvgvDwgKijqOTLviIfz  1
		$a_80_4 = {58 58 6b 55 50 49 6e 43 48 55 6d 64 48 4c 6a 65 72 72 78 6a 79 7a 64 46 4e 5a } //XXkUPInCHUmdHLjerrxjyzdFNZ  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}