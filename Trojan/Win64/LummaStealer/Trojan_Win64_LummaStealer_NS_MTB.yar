
rule Trojan_Win64_LummaStealer_NS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 0a 0f 83 ee 0e fc ff 66 41 89 01 48 8d 64 24 ?? e9 f5 31 fc ff } //3
		$a_03_1 = {e8 51 3c fd ff 33 c9 48 f7 54 24 ?? 4d 85 d2 48 8d 64 24 ?? 0f 84 74 7d fe ff } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_LummaStealer_NS_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 1d b1 33 43 00 48 8d 05 82 b5 23 00 48 8d 0d 3d cd 19 00 bf 04 00 00 00 48 8d 35 01 57 1a 00 41 b8 19 00 00 00 45 31 c9 } //2
		$a_01_1 = {48 8b 3a 48 8b 72 08 31 c0 48 8d 1d cb d1 19 00 b9 04 00 00 00 e8 a3 a3 d1 ff 48 89 9c 24 28 02 00 00 48 89 84 24 20 02 00 00 48 8d 05 1f dc 19 00 bb 07 00 00 00 48 8d 8c 24 10 02 00 00 bf 02 00 00 00 48 89 fe e8 12 66 dd ff e8 6d 77 dd ff 48 8b ac 24 60 05 00 00 48 81 c4 68 05 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}