
rule _#do_deep_rescan{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {98 89 04 10 dc e8 6a 43 dc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_2{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a7 6e 19 a6 90 09 03 00 c7 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_3{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 72 6f 74 65 e8 } //1
		$a_01_1 = {68 56 69 72 74 } //1 hVirt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_deep_rescan_4{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 00 04 00 00 31 d2 b9 36 07 03 00 f3 ab 8b 45 0c 6a 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_5{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 6d 52 43 34 90 05 07 01 00 6d 52 75 6e 50 45 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_6{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f9 f5 0f 82 ?? ?? ?? ?? 81 90 09 06 00 81 ?? ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_7{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 3c 3b 44 24 (24|20) 0f 85 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_8{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 08 81 fb ?? ?? ?? ?? eb ?? ?? [0-04] e9 90 16 ff 34 24 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_9{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 6f 76 6e 2d 61 76 61 73 74 21 00 } //1 潧湶愭慶瑳!
		$a_01_1 = {77 64 73 75 78 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_deep_rescan_10{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {79 fc fc 31 c9 89 c8 31 d2 f6 35 ?? ?? ?? ?? 86 e0 30 e4 02 80 ?? ?? ?? ?? 02 81 ?? ?? ?? ?? 00 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_11{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 6d fc 30 00 00 00 f7 55 fc 83 6d fc ff ff 75 d8 ff 75 fc ff 75 f4 8d ?? 58 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_12{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 0c 33 d2 52 50 8b 44 24 ?? 99 03 04 ?? 13 54 ?? 04 83 c4 08 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_13{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 69 64 65 72 65 64 5c 4f 74 68 65 72 77 69 73 65 5c 49 6e 73 74 61 6e 63 65 73 2e 70 64 62 } //1 Considered\Otherwise\Instances.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_14{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_11_0 = {c0 64 8b 40 30 56 85 c0 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 83 c0 7c 8b 40 3c 5e c3 00 } //1
	condition:
		((#a_11_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_15{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 62 67 8d a4 ff 75 ?? e8 ?? ?? ?? ?? 50 6a 00 68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e 54 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_16{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 6d fc 30 00 00 00 [0-05] f7 55 fc [0-05] ff 75 d8 ff 75 fc ff 75 f4 8d ?? 58 fe ff ff ?? e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_17{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 83 c7 04 81 fe ?? ?? ?? ?? 75 ?? 81 c7 ?? ?? ?? ?? 01 d7 50 58 ff e7 90 0a 60 00 be 00 00 00 00 bf 00 00 00 00 ba 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_18{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 37 00 00 [0-20] (7d|0f 8d) [0-20] 7f 02 00 00 [0-20] (7d|0f 8d) [0-20] 7f [0-20] (|) 7f 0f 8f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule _#do_deep_rescan_19{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 3c 41 72 06 3c 5a 77 02 04 20 aa e2 f2 81 7d ?? 6b 65 72 6e 75 c7 81 7d ?? 65 6c 33 32 75 be 81 7d ?? 2e 64 6c 6c 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_20{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {21 54 45 6e 69 67 6d 61 50 72 6f 74 65 63 74 6f 72 4c 6f 61 64 65 72 } //1 !TEnigmaProtectorLoader
		$a_00_1 = {4f 4c 4c 59 44 42 47 } //1 OLLYDBG
		$a_00_2 = {76 6d 77 61 72 65 } //1 vmware
		$a_00_3 = {73 61 6e 64 62 6f 78 } //1 sandbox
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#do_deep_rescan_21{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ed 05 10 40 00 8a 9d ?? ?? ?? ?? 84 db 74 13 81 c4 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 85 ?? 12 40 00 eb 19 c7 85 ?? 14 40 00 22 22 22 22 c7 85 ?? 14 40 00 33 33 33 33 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_22{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {90 83 ec 7c 8b 94 24 90 00 00 00 c7 44 24 74 00 00 00 00 c6 44 24 73 00 8b ac 24 9c 00 00 00 8d 42 04 89 44 24 78 b8 01 00 00 00 0f b6 4a 02 89 c3 d3 e3 89 d9 49 89 4c 24 6c 0f b6 4a 01 d3 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_23{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 fc ba 09 00 00 00 e8 ?? ?? ?? ?? 8b 55 fc 8b 83 ?? ?? 00 00 e8 ?? ?? ?? ?? 8d 4d ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b2 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_deep_rescan_24{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 ff d0 40 e8 00 00 00 00 2d ?? ?? ?? ?? 01 04 24 ff 14 24 2d ?? ?? ?? ?? 83 7d f4 00 75 05 } //1
		$a_03_1 = {58 ff d0 40 e8 00 00 00 00 2d ?? ?? ?? ?? 01 04 24 8b 04 24 ff d0 2d ?? ?? ?? ?? 83 7d f4 00 75 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_deep_rescan_25{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 00 00 10 75 90 09 03 00 81 7d } //1
		$a_03_1 = {02 00 00 10 74 90 09 03 00 81 7d } //1
		$a_03_2 = {ff ff 02 00 00 10 75 90 09 04 00 81 bd } //1
		$a_03_3 = {ff ff 02 00 00 10 74 90 09 04 00 81 bd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}
rule _#do_deep_rescan_26{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {68 9b 5b 14 fb } //1
		$a_01_1 = {68 bc 0c c6 73 } //1
		$a_01_2 = {68 66 53 02 42 } //1
		$a_01_3 = {68 ab 68 03 f4 } //1
		$a_01_4 = {68 5e c4 f7 ee } //1
		$a_01_5 = {68 13 71 0b b1 } //1
		$a_01_6 = {68 b6 ff 24 33 } //1
		$a_01_7 = {68 c1 2e d8 f1 } //1
		$a_01_8 = {68 f7 d2 6c 79 } //1
		$a_01_9 = {35 82 fa 50 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=2
 
}
rule _#do_deep_rescan_27{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 18 43 81 3b 72 73 72 63 74 } //2
		$a_01_1 = {66 c7 45 fc 63 74 c6 45 fe 00 60 8d 45 ec 50 } //1
		$a_01_2 = {c7 45 f0 56 69 72 74 c7 45 f4 75 61 6c 41 } //1
		$a_01_3 = {55 89 e5 83 ec 20 c7 45 e0 56 69 72 74 c7 45 e4 75 61 6c 41 } //1
		$a_01_4 = {c7 45 fc 00 00 00 00 60 8b 75 08 03 76 3c 0f b7 56 06 4a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
rule _#do_deep_rescan_28{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 28 8b c6 3b c1 72 ?? 8b 45 ?? 8b 4f 04 } //1
		$a_03_1 = {8b 4e 28 8b c7 3b c1 72 ?? 8b 45 ?? 8b 4e 04 } //1
		$a_01_2 = {53 00 45 00 4c 00 46 00 55 00 50 00 44 00 41 00 54 00 45 00 00 00 } //10
		$a_01_3 = {2f 00 53 00 45 00 52 00 56 00 49 00 43 00 45 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=21
 
}
rule _#do_deep_rescan_29{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {c9 c2 10 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_1 = {c9 c2 0c 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_2 = {c9 c2 14 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_3 = {c9 c2 1c 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}
rule _#do_deep_rescan_30{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 00 44 00 41 00 54 00 41 00 00 00 } //1
		$a_01_1 = {00 42 44 41 54 41 00 } //1
		$a_03_2 = {50 68 24 27 00 00 e8 [0-40] 51 68 2e 27 00 00 e8 } //2
		$a_01_3 = {8d 44 24 14 50 68 1a 27 00 00 e8 } //2
		$a_03_4 = {50 6a 65 e8 ?? ?? ?? ?? 8d 4c 24 ?? 8b d1 [0-40] 51 6a 66 e8 ?? ?? ?? ?? 8b 54 24 } //2
		$a_03_5 = {c6 02 00 c7 44 24 2c 01 00 00 00 50 6a 64 e8 ?? ?? ?? ?? 8b 4c 24 24 8b 54 24 20 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2) >=2
 
}
rule _#do_deep_rescan_31{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {43 c1 ea 08 47 83 ff 04 75 0a ba ?? ?? ?? ?? bf 00 00 00 00 81 fb ?? ?? ?? ?? 72 dd 90 09 15 00 33 ?? ba ?? ?? ?? ?? 33 ff bb ?? ?? ?? ?? 83 ?? 00 75 02 28 13 } //1
		$a_02_1 = {28 13 43 c1 ea 08 41 83 f9 04 75 0a ba ?? ?? ?? ?? b9 00 00 00 00 81 fb ?? ?? ?? 00 72 e2 90 09 07 00 33 c9 ba } //1
		$a_02_2 = {83 f8 00 75 02 28 11 41 c1 ea 08 47 83 ff 04 75 0a ba ?? ?? ?? ?? bf 00 00 00 00 81 f9 ?? ?? ?? 00 72 dd 90 09 0e 00 33 c0 ba ?? ?? ?? ?? 33 ff b9 ?? ?? ?? 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule _#do_deep_rescan_32{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 8b 5d fc 8b 0c 99 8b 5d 0c 03 cf 89 5d f8 8b 5d f8 8a 1b 3a 19 } //1
		$a_01_1 = {8b 5d f8 8a 5b 01 88 5d 0b 3a 59 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_deep_rescan_33{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 6a 05 5f f7 f7 8b f9 33 fe } //1
		$a_01_1 = {e9 06 00 00 00 81 00 aa 9b 78 ff } //1
		$a_01_2 = {66 89 45 e8 6a 10 58 66 89 45 ea 8d 45 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_deep_rescan_34{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 25 65 76 69 72 44 6c 61 63 69 73 79 68 50 5c 2e 5c 5c } //1 d%evirDlacisyhP\.\\
		$a_01_1 = {71 26 64 25 3d 64 69 75 26 3f } //1 q&d%=diu&?
		$a_01_2 = {26 73 25 3d 6c 74 74 26 64 25 3d 64 69 75 26 65 74 61 64 70 75 3d 65 70 79 54 70 75 74 65 73 } //1 &s%=ltt&d%=diu&etadpu=epyTputes
		$a_01_3 = {74 73 6f 68 5c 63 74 65 5c 73 72 65 76 69 72 64 } //1 tsoh\cte\srevird
		$a_01_4 = {73 00 79 00 73 00 2e 00 73 00 25 00 5c 00 73 00 25 00 } //1 sys.s%\s%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#do_deep_rescan_35{
	meta:
		description = "!#do_deep_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 73 79 6e 65 72 67 69 2e 64 6b 2f 64 61 74 61 } //1 http://psynergi.dk/data
		$a_01_1 = {68 74 74 70 3a 2f 2f 6b 75 62 75 73 73 65 2e 72 75 2f 64 61 74 61 } //1 http://kubusse.ru/data
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 2d 65 6c 69 73 61 2e 72 75 2f 64 61 74 61 } //1 http://s-elisa.ru/data
		$a_01_3 = {68 74 74 70 3a 2f 2f 65 64 61 2e 72 75 2f 64 61 74 61 } //1 http://eda.ru/data
		$a_01_4 = {68 74 74 70 3a 2f 2f 76 65 73 74 65 72 6d 2e 66 72 65 65 68 6f 73 74 69 61 2e 63 6f 6d } //1 http://vesterm.freehostia.com
		$a_01_5 = {2e 78 31 30 68 6f 73 74 69 6e 67 2e 63 6f 6d } //1 .x10hosting.com
		$a_01_6 = {2e 61 77 61 72 64 73 70 61 63 65 2e 63 6f 6d } //1 .awardspace.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}