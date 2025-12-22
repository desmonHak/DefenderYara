
rule Trojan_Win32_CoinMiner_AMTB{
	meta:
		description = "Trojan:Win32/CoinMiner!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {63 6f 69 6e 22 3a 20 22 58 4d 52 22 } //coin": "XMR"  2
		$a_80_1 = {38 63 70 75 2e 75 } //8cpu.u  2
		$a_80_2 = {72 69 67 2d 69 64 22 3a 20 22 76 70 73 2d 30 30 31 } //rig-id": "vps-001  2
		$a_80_3 = {22 68 75 67 65 2d 70 61 67 65 73 22 3a 20 74 72 75 65 } //"huge-pages": true  2
		$a_80_4 = {22 64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 22 3a 20 31 } //"donate-over-proxy": 1  2
		$a_80_5 = {22 6e 69 63 65 68 61 73 68 22 3a 20 74 72 75 65 } //"nicehash": true  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=12
 
}