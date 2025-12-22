
rule _#PUA_Block_lolMiner{
	meta:
		description = "!#PUA:Block:lolMiner,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 6c 4d 69 6e 65 72 20 64 6f 65 73 20 6e 6f 74 20 6b 6e 6f 77 20 77 68 61 74 20 74 6f 20 64 6f } //1 lolMiner does not know what to do
		$a_01_1 = {42 69 74 63 6f 69 6e } //1 Bitcoin
		$a_01_2 = {45 78 63 68 61 6e 67 65 20 43 6f 69 6e } //1 Exchange Coin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_lolMiner_2{
	meta:
		description = "!#PUA:Block:lolMiner,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 62 00 6f 00 75 00 74 00 20 00 6c 00 6f 00 6c 00 4d 00 69 00 6e 00 65 00 72 00 47 00 55 00 49 00 } //2 About lolMinerGUI
		$a_01_1 = {5c 6c 6f 6c 4d 69 6e 65 72 47 55 49 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6c 6f 6c 4d 69 6e 65 72 47 55 49 2e 70 64 62 } //2 \lolMinerGUI\x64\Release\lolMinerGUI.pdb
		$a_01_2 = {4f 00 43 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 65 00 6e 00 20 00 61 00 70 00 70 00 6c 00 69 00 65 00 64 00 2e 00 20 00 52 00 75 00 6e 00 20 00 61 00 73 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 } //1 OCs will not been applied. Run as Administrator
		$a_01_3 = {4d 00 43 00 4c 00 4b 00 20 00 6c 00 6f 00 77 00 65 00 72 00 20 00 74 00 68 00 61 00 6e 00 20 00 35 00 30 00 30 00 30 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6f 00 6e 00 6c 00 79 00 20 00 61 00 70 00 70 00 6c 00 79 00 20 00 74 00 6f 00 20 00 41 00 6d 00 70 00 65 00 72 00 65 00 20 00 61 00 6e 00 64 00 20 00 41 00 44 00 41 00 } //1 MCLK lower than 5000 will only apply to Ampere and ADA
		$a_01_4 = {6c 00 6f 00 6c 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 2d 00 61 00 20 00 41 00 4c 00 47 00 4f 00 20 00 2d 00 70 00 20 00 50 00 4f 00 4f 00 4c 00 20 00 2d 00 75 00 20 00 57 00 41 00 4c 00 4c 00 45 00 54 00 2e 00 57 00 4f 00 52 00 4b 00 45 00 52 00 4e 00 41 00 4d 00 45 00 } //1 lolminer.exe -a ALGO -p POOL -u WALLET.WORKERNAME
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}