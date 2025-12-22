
rule TrojanDropper_O97M_ZooFlip_C_dha{
	meta:
		description = "TrojanDropper:O97M/ZooFlip.C!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 69 6d 74 73 69 61 73 73 69 77 69 74 68 74 73 69 2e 63 62 3d 6c 65 6e 62 28 74 73 69 29 2e 64 66 3d 73 75 71 6f 72 73 75 68 71 2e 77 73 77 3d 73 68 71 65 6e 64 77 69 74 68 } //1 dimtsiassiwithtsi.cb=lenb(tsi).df=suqorsuhq.wsw=shqendwith
		$a_03_1 = {64 69 6d 74 73 61 [0-15] 61 73 70 69 64 69 6d [0-20] 61 73 73 74 72 69 6e 67 64 69 6d [0-20] 61 73 6c 6f 6e 67 [0-30] 28 30 26 2c 73 74 72 70 74 72 28 [0-10] 29 2c 30 26 2c 30 26 2c 74 72 75 65 2c 30 26 2c 62 79 76 61 6c 30 26 2c 73 74 72 70 74 72 28 } //1
		$a_03_2 = {74 79 70 65 73 69 63 62 61 73 6c 6f 6e 67 [0-03] 6c 72 61 73 6c 6f 6e 67 [0-03] 6c 64 61 73 6c 6f 6e 67 [0-03] 6c 74 61 73 6c 6f 6e 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}