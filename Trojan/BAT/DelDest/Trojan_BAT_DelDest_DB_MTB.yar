
rule Trojan_BAT_DelDest_DB_MTB{
	meta:
		description = "Trojan:BAT/DelDest.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 68 61 6e 68 61 69 } //20 shanhai
		$a_81_1 = {42 59 44 53 63 72 65 65 6e 41 6e 64 4d 65 73 32 30 32 32 31 32 32 31 5c 44 62 52 65 70 6f 73 69 74 6f 72 79 } //1 BYDScreenAndMes20221221\DbRepository
		$a_81_2 = {47 65 74 4c 6f 67 52 65 70 6f 73 69 74 6f 72 79 } //1 GetLogRepository
		$a_81_3 = {75 73 65 72 20 69 64 3d 73 61 3b 70 61 73 73 77 6f 72 64 3d 31 32 33 34 35 36 } //20 user id=sa;password=123456
		$a_81_4 = {69 6e 69 74 69 61 6c 20 63 61 74 61 6c 6f 67 3d 42 59 44 53 41 5f 43 53 31 } //1 initial catalog=BYDSA_CS1
		$a_81_5 = {64 61 74 61 20 73 6f 75 72 63 65 3d 31 32 37 2e 30 2e 30 2e 31 5c 4a 43 } //1 data source=127.0.0.1\JC
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=22
 
}