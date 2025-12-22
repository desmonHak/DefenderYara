
rule Trojan_BAT_Cerbu_ARR_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 2d 48 6f 73 74 20 22 73 65 6e 64 20 74 6f 20 31 38 6f 38 65 4b 72 38 53 6e 33 45 42 70 47 6a 4e 6d 58 56 34 58 64 70 45 4d 35 48 63 31 46 7a 74 65 22 } //20 Write-Host "send to 18o8eKr8Sn3EBpGjNmXV4XdpEM5Hc1Fzte"
		$a_01_1 = {24 67 69 66 70 61 74 68 20 3d 20 24 70 77 64 2e 50 61 74 68 2b 27 5c 73 76 63 68 6f 73 74 2e 65 78 65 27 } //10 $gifpath = $pwd.Path+'\svchost.exe'
		$a_81_2 = {74 65 73 74 31 2e 65 78 65 } //19 test1.exe
		$a_03_3 = {11 14 02 11 15 9a 6f ?? ?? ?? ?? 13 16 11 16 } //1
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_81_2  & 1)*19+(#a_03_3  & 1)*1) >=50
 
}