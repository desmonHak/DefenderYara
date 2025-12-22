
rule Trojan_BAT_Quasarrat_PGQR_MTB{
	meta:
		description = "Trojan:BAT/Quasarrat.PGQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {71 44 32 4e 61 6c 45 76 4c 6d 2f 59 48 4d 67 34 6a 51 67 4a 64 33 35 48 65 4d 45 54 61 36 6a 45 51 64 5a 50 32 61 4e 44 31 6d 4f 34 36 73 63 65 47 77 7a 66 6c 57 6f 74 68 30 4c 2b 37 43 73 75 79 76 6a 6c 4c 6a 76 44 77 38 4d 69 53 35 45 70 79 75 4e 70 35 4d 72 34 35 53 34 37 77 38 50 44 49 6b 75 52 4b 63 72 6a 61 65 53 51 2f 43 79 31 50 66 38 63 2f 78 47 41 44 4b 6e 7a 49 54 } //qD2NalEvLm/YHMg4jQgJd35HeMETa6jEQdZP2aND1mO46sceGwzflWoth0L+7CsuyvjlLjvDw8MiS5EpyuNp5Mr45S47w8PDIkuRKcrjaeSQ/Cy1Pf8c/xGADKnzIT  5
		$a_80_1 = {31 32 39 39 2e 65 78 65 } //1299.exe  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}