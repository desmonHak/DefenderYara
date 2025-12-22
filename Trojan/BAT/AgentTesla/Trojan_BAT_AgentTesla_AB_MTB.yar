
rule Trojan_BAT_AgentTesla_AB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 c7 0b 00 00 95 2e 03 16 2b 04 17 06 13 04 17 59 7e 27 00 00 04 20 a3 11 00 00 95 5f 7e 27 00 00 04 20 d8 01 00 00 95 61 61 80 14 00 00 04 } //4
		$a_01_1 = {20 b5 09 00 00 95 e0 95 7e 0a 00 00 04 20 b0 0c 00 00 95 61 7e 0a 00 00 04 20 cd 02 00 00 95 2e 03 17 2b 01 16 58 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=4
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {15 2d 0a 26 02 8e 69 16 2c 0a 26 2b 17 28 02 00 00 06 2b f0 0a 2b f4 28 01 00 00 06 02 06 91 6f 1e 00 00 0a 06 25 17 59 1b 2d 0a 26 16 fe 02 0b 07 2d e4 2b 03 0a 2b f4 } //10
		$a_00_1 = {57 15 02 08 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 30 00 00 00 05 00 00 00 05 00 00 00 10 00 00 00 04 00 00 00 37 } //3
		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
		$a_81_3 = {57 65 62 52 65 71 75 65 73 74 } //3 WebRequest
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=16
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 29 11 16 1f 41 61 13 16 11 16 1f 4b 59 45 06 00 00 00 0b 00 00 00 1c 00 00 00 34 00 00 00 43 00 00 00 59 00 00 00 66 00 00 00 1f 42 28 ?? 00 00 06 13 16 2b cc 11 0c 11 0d fe 01 16 fe 01 13 0e 1f 0e 13 16 2b bb 11 08 11 0b 5f 11 0a 1f 1f 5f 63 13 0d 1f 3d 28 ?? 00 00 06 13 16 2b a3 } //2
		$a_01_1 = {24 36 64 61 65 63 31 31 39 2d 31 63 32 31 2d 34 37 61 62 2d 39 37 63 66 2d 61 35 31 38 35 35 62 64 34 34 34 31 } //2 $6daec119-1c21-47ab-97cf-a51855bd4441
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 06 20 ?? 00 00 00 91 1a 5b 13 05 2b b5 16 0a 1b 13 05 2b ae 0e 04 05 61 1f 6e 59 06 61 45 ?? ?? ?? ?? ?? ?? ?? ?? 1d 13 05 2b 97 11 06 20 dd 00 00 00 91 11 06 20 d3 00 00 00 91 59 2b e9 12 02 fe ?? 21 00 00 01 08 0b 11 06 1f 50 91 13 05 38 ?? ff ff ff 02 8c 01 00 00 1b 03 04 6f ?? 00 00 0a 0b 1a 13 05 38 ?? ff ff ff 06 17 58 0a 05 25 5a 0d 05 09 58 0d 11 06 20 f0 00 00 00 91 1f 0d 59 13 05 38 ?? ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 65 6e 64 41 6c 6c 54 65 78 74 } //1 AppendAllText
		$a_01_1 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //1 WriteAllText
		$a_01_2 = {54 72 69 6d 45 6e 64 } //1 TrimEnd
		$a_01_3 = {54 72 61 6e 73 61 63 74 69 6f 6e } //1 Transaction
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 } //1 get_Current
		$a_01_5 = {67 65 74 5f 54 72 61 6e 73 61 63 74 69 6f 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 get_TransactionInformation
		$a_01_6 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_7 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_8 = {54 72 61 6e 73 61 63 74 69 6f 6e 61 6c 46 69 6c 65 4d 61 6e 61 67 65 72 2e 64 6c 6c } //1 TransactionalFileManager.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}