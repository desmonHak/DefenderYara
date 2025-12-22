
rule _#Adware_Win32_GameVance{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb ff ff 56 69 72 74 90 09 04 00 3e 81 bd } //1
		$a_03_1 = {eb ff ff 75 61 6c 51 90 09 04 00 3e 81 bd } //1
		$a_03_2 = {f4 ff ff 2e 72 73 72 90 09 04 00 3e 81 bd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_2{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 69 76 61 6c 47 61 6d 69 6e 67 2e 78 70 74 } //1 RivalGaming.xpt
		$a_01_1 = {6d 69 74 65 78 5f 63 66 67 5f 74 72 63 69 } //1 mitex_cfg_trci
		$a_01_2 = {6d 69 6e 67 2e 63 6f 6d 00 } //1
		$a_01_3 = {2e 66 75 73 69 6f 6e 6c 6f 61 64 } //1 .fusionload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_3{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 70 69 63 48 6f 73 74 2e 64 6c 6c } //1 epicHost.dll
		$a_01_1 = {65 70 6c 61 79 5f 77 6e 64 74 69 74 6c 65 5f 73 74 72 69 6e 67 } //1 eplay_wndtitle_string
		$a_01_2 = {65 70 69 63 70 6c 61 79 2e 63 6f 6d } //1 epicplay.com
		$a_01_3 = {47 41 4d 2d 53 52 53 2d 54 33 } //1 GAM-SRS-T3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_4{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8a 0c 02 80 f1 ?? 88 08 74 08 46 40 3b 74 24 08 7c ee } //1
		$a_03_1 = {04 73 10 8b ?? 08 0f be 14 ?? 83 f2 ?? 88 14 ?? (40|41) eb e8 } //1
		$a_01_2 = {7c 6d 61 63 3d 25 73 7c } //1 |mac=%s|
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_5{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {58 30 58 30 [0-30] 59 30 59 30 [0-30] 4c 49 4c 49 } //1
		$a_03_1 = {68 d0 4f e8 56 9c 81 ?? ?? ?? 31 b0 17 a9 9d ff 15 ?? ?? ?? ?? eb } //1
		$a_03_2 = {03 04 24 89 04 24 58 90 09 0d 00 81 c0 ?? ?? ?? ?? 81 2c 24 90 1b 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_6{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {67 61 6d 65 76 61 6e 63 65 2e (63 6f 6d|6e 65 74) } //1
		$a_00_1 = {77 6d 5f 66 69 72 65 5f 62 69 67 5f 70 6f 70 75 70 } //1 wm_fire_big_popup
		$a_00_2 = {6d 79 5f 74 68 72 5f 6d 75 74 5f 25 64 } //1 my_thr_mut_%d
		$a_00_3 = {37 32 2e 32 33 32 2e 34 33 2e 32 32 36 } //1 72.232.43.226
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_7{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e 81 bd 50 e9 ff ff 54 59 54 59 eb 05 90 3e d0 67 65 75 20 eb 04 } //1
		$a_01_1 = {3e 81 bd a0 e8 ff ff 4c 49 4c 49 eb 05 9c 9e 74 07 a4 0f 84 0b 02 00 00 eb 01 } //1
		$a_01_2 = {3e 81 bd a0 e8 ff ff 58 30 58 30 eb 01 1e 0f 84 b8 02 00 00 eb 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_8{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f8 8b 4d f8 03 48 3c 89 4d d0 } //1
		$a_01_1 = {83 bd 64 ff ff ff 10 } //1
		$a_01_2 = {83 7d 8c 14 } //1
		$a_03_3 = {9c 81 44 24 04 ?? ?? ?? ?? 9d 6a 00 } //2
		$a_03_4 = {9c 81 45 a0 ?? ?? ?? ?? 9d } //1
		$a_01_5 = {8a 88 14 01 00 00 88 4a 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule _#Adware_Win32_GameVance_9{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 50 54 65 78 74 4c 69 6e 6b 73 } //1 PPTextLinks
		$a_01_1 = {63 66 2e 70 6c 70 69 63 6b 6c 65 2e 63 6f 6d } //1 cf.plpickle.com
		$a_01_2 = {70 70 5f 63 6f 6e 66 69 67 5f 74 68 72 65 61 64 5f 6d 74 78 } //1 pp_config_thread_mtx
		$a_01_3 = {50 6c 61 79 50 69 63 6b 6c 65 54 65 78 74 2e 54 6f 6f 6c 62 61 72 } //1 PlayPickleText.Toolbar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_10{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 61 74 61 4c 6f 77 5c 46 72 65 65 57 6f 72 6b 7a 53 65 74 74 69 6e 67 73 } //1 AppDataLow\FreeWorkzSettings
		$a_01_1 = {63 6f 6e 74 65 6e 74 2e 66 72 65 65 77 6f 72 6b 7a 67 61 6d 65 73 2e 63 6f 6d } //1 content.freeworkzgames.com
		$a_01_2 = {6c 69 6e 6b 73 40 66 72 65 65 77 6f 72 6b 7a 2e 63 6f 6d } //1 links@freeworkz.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_11{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 65 78 74 6c 69 6e 6b 73 40 6c 70 6c 61 79 2e 63 6f 6d } //1 textlinks@lplay.com
		$a_01_1 = {6c 70 5f 63 6f 6e 66 69 67 5f 74 68 72 65 61 64 5f 6d 74 78 } //1 lp_config_thread_mtx
		$a_01_2 = {4c 69 76 69 6e 67 50 6c 61 79 20 47 61 6d 65 73 } //1 LivingPlay Games
		$a_01_3 = {63 66 2e 6c 69 76 69 6e 67 70 6c 61 79 2e 63 6f 6d } //1 cf.livingplay.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_12{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 76 61 6e 63 65 2e 63 6f 6d 00 } //1
		$a_01_1 = {47 61 6d 65 76 61 6e 63 65 54 65 78 74 2e 4c 69 6e 6b 65 72 2e 31 } //1 GamevanceText.Linker.1
		$a_01_2 = {64 61 74 61 2e 35 74 68 72 65 76 6f 6c 75 74 69 6f 6e 2e 63 6f 6d 00 } //1
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 67 76 74 6c } //1 Software\gvtl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_13{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 32 33 65 63 6e 61 76 65 6d 61 67 00 } //1
		$a_01_1 = {2e 6e 6f 69 74 61 6c 6c 61 74 73 6e 69 20 65 63 6e 61 76 65 6d 61 47 } //1 .noitallatsni ecnavemaG
		$a_01_2 = {6c 74 76 67 5c 65 72 61 77 74 66 6f 53 00 } //1 瑬杶敜慲瑷潦S
		$a_01_3 = {6d 6f 63 2e 6e 6f 69 74 75 6c 6f 76 65 72 68 74 35 2e 61 74 61 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_14{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 00 61 00 6d 00 65 00 76 00 61 00 6e 00 63 00 65 00 5c 00 61 00 72 00 73 00 2e 00 63 00 66 00 67 00 } //1 Gamevance\ars.cfg
		$a_01_1 = {47 61 6d 65 76 61 6e 63 65 54 65 78 74 2e } //1 GamevanceText.
		$a_01_2 = {67 61 6d 65 76 61 6e 63 65 2e 63 6f 6d 00 } //1
		$a_01_3 = {41 56 43 47 61 6d 65 76 61 6e 63 65 54 65 78 74 4d 6f 64 75 6c 65 40 40 } //1 AVCGamevanceTextModule@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_15{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 65 6e 74 5f 69 6e 73 74 61 6c 6c 5f 6d 74 78 5f 41 42 43 44 00 } //1 汣敩瑮楟獮慴汬浟硴䅟䍂D
		$a_00_1 = {61 72 73 2e 63 66 67 } //1 ars.cfg
		$a_01_2 = {70 6c 61 79 70 69 63 6b 6c 65 77 6e 61 6d 65 00 70 6c 61 79 70 69 63 6b 6c 65 63 6c 61 73 73 00 } //1 汰祡楰正敬湷浡e汰祡楰正敬汣獡s
		$a_00_3 = {70 70 5f 72 69 6e 67 65 72 61 6a 61 } //1 pp_ringeraja
		$a_00_4 = {67 72 73 5f 7a 7a 5f 70 70 } //1 grs_zz_pp
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_16{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {47 61 6d 65 76 61 6e 63 65 [0-04] 2e 44 4c 4c [0-02] 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10
		$a_00_1 = {2e 67 61 6d 65 76 61 6e 63 65 2e 63 6f 6d } //10 .gamevance.com
		$a_00_2 = {5c 67 76 74 6c } //1 \gvtl
		$a_00_3 = {37 32 2e 32 33 32 2e 34 33 2e 32 32 36 } //1 72.232.43.226
		$a_00_4 = {35 74 68 72 65 76 6f 6c 75 74 69 6f 6e 2e 63 6f 6d } //1 5threvolution.com
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}
rule _#Adware_Win32_GameVance_17{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {67 61 6d 65 76 61 6e 63 65 6c 69 62 33 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 慧敭慶据汥扩㈳搮汬䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣䐀汬敒楧瑳牥敓癲牥䐀汬湕敲楧瑳牥敓癲牥
		$a_03_1 = {9c 81 44 24 04 ?? ?? ?? ?? 9d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_18{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {9c 81 44 24 04 ?? ?? ?? ?? 9d } //1
		$a_03_1 = {ff 70 3c 81 c1 ?? ?? ?? ?? 81 2c 24 ?? ?? ?? ?? 03 0c 24 89 0c 24 } //1
		$a_03_2 = {ff 75 08 59 ff 70 5c 81 c1 ?? ?? ?? ?? 81 2c 24 ?? ?? ?? ?? 03 0c 24 } //1
		$a_00_3 = {67 76 74 6c 66 2e 64 6c 6c 00 4e 53 47 65 74 4d 6f 64 75 6c 65 00 } //1
		$a_00_4 = {00 43 72 79 70 74 47 65 74 48 61 73 68 50 61 72 61 6d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_19{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 02 00 00 00 eb 90 14 3e c7 85 ?? ?? ff ff 00 00 00 00 eb 90 14 eb 90 14 3e 81 bd ?? ?? ff ff 8c 00 00 00 eb } //1
		$a_03_1 = {fd ff ff 47 eb [0-08] 3e c6 85 ?? ?? ff ff 65 eb [0-08] 3e c6 85 ?? ?? ff ff 74 eb [0-08] 3e c6 85 ?? ?? ff ff 4d eb [0-08] 3e c6 85 ?? ?? ff ff 6f eb [0-08] 3e c6 85 ?? ?? ff ff 64 eb } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}
rule _#Adware_Win32_GameVance_20{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 85 08 fe ff ff 47 c6 85 09 fe ff ff 65 c6 85 0a fe ff ff 74 c6 85 0b fe ff ff 53 c6 85 0c fe ff ff 79 c6 85 0d fe ff ff 73 } //1
		$a_03_1 = {ff ff 2e 72 73 72 (75|eb) } //1
		$a_03_2 = {9c 81 44 24 04 ?? ?? ?? ?? 9d } //1
		$a_01_3 = {72 eb 04 59 3e d3 0a 3e c6 85 69 eb ff ff 72 eb 03 48 a4 45 3e c6 85 6a eb ff ff 6f eb 03 a4 5a 27 3e c6 85 6b eb ff ff 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule _#Adware_Win32_GameVance_21{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 65 6e 74 5f 69 6e 73 74 61 6c 6c 5f 6d 74 78 5f 41 42 43 44 00 } //1 汣敩瑮楟獮慴汬浟硴䅟䍂D
		$a_01_1 = {67 72 73 63 6c 61 73 73 00 } //1
		$a_01_2 = {70 6c 61 79 70 69 63 6b 6c 65 77 6e 61 6d 65 00 70 6c 61 79 70 69 63 6b 6c 65 63 6c 61 73 73 00 } //1 汰祡楰正敬湷浡e汰祡楰正敬汣獡s
		$a_01_3 = {70 70 5f 69 6e 73 74 61 6c 6c 65 72 5f 6d 74 78 00 } //1
		$a_01_4 = {62 6c 6c 65 66 6b 62 70 62 65 66 64 6f 64 69 69 65 66 70 6b 63 6e 69 67 70 69 63 6d 68 6f 68 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_22{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 76 61 6e 63 65 20 54 65 78 74 20 70 6c 75 67 69 6e 2e 00 } //1
		$a_01_1 = {5c 41 70 70 44 61 74 61 4c 6f 77 5c 67 76 74 6c } //1 \AppDataLow\gvtl
		$a_01_2 = {6c 75 2e 67 61 6d 65 76 61 6e 63 65 2e 63 6f 6d 00 } //1
		$a_01_3 = {63 69 64 3a 25 64 7c 75 69 64 3a 25 73 7c 6c 69 64 3a 25 64 7c 6a 73 73 3a 25 64 7c 73 63 32 63 31 3a 25 64 7c 73 63 32 63 32 3a 25 64 7c 66 6c 3a 25 73 7c 74 69 3a 25 73 7c 63 72 63 3a 25 73 } //1 cid:%d|uid:%s|lid:%d|jss:%d|sc2c1:%d|sc2c2:%d|fl:%s|ti:%s|crc:%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_23{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff ff 2e 72 73 72 75 } //1
		$a_03_1 = {9c 81 44 24 04 ?? ?? ?? ?? 9d 8b 85 ?? ?? ff ff 8b 48 ?? ff d1 } //1
		$a_03_2 = {ff ff 55 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 68 c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_24{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 69 76 61 6c 47 61 6d 69 6e 67 44 61 74 61 } //1 RivalGamingData
		$a_01_1 = {61 6a 2f 64 65 61 63 74 69 76 61 74 65 2e 70 68 70 } //1 aj/deactivate.php
		$a_01_2 = {61 6a 2f 69 6e 73 74 2e 70 68 70 } //1 aj/inst.php
		$a_01_3 = {52 69 76 61 6c 47 61 6d 69 6e 67 2e 78 70 74 } //1 RivalGaming.xpt
		$a_01_4 = {6d 69 6e 67 2e 63 6f 6d 00 00 00 00 2e 72 69 76 61 6c 67 61 00 } //1
		$a_01_5 = {72 67 5f 75 70 64 61 74 65 2e 65 78 65 } //1 rg_update.exe
		$a_01_6 = {72 69 76 61 6c 67 61 6d 69 6e 67 67 63 2e 6a 73 } //1 rivalgaminggc.js
		$a_01_7 = {6d 65 74 65 78 5f 63 66 67 5f 72 75 6e 00 } //1 敭整彸晣彧畲n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_25{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 07 00 00 "
		
	strings :
		$a_00_0 = {61 6a 2f 64 65 61 63 74 69 76 61 74 65 2e 70 68 70 } //100 aj/deactivate.php
		$a_00_1 = {46 72 65 65 77 6f 72 6b 7a 20 55 6e 69 6e 73 74 61 6c 6c 65 72 } //10 Freeworkz Uninstaller
		$a_00_2 = {50 6c 61 79 20 50 69 63 6b 6c 65 20 55 6e 69 6e 73 74 61 6c 6c 65 72 } //10 Play Pickle Uninstaller
		$a_00_3 = {4c 69 76 69 6e 67 50 6c 61 79 20 75 6e 69 6e 73 74 61 6c 6c 65 72 } //10 LivingPlay uninstaller
		$a_02_4 = {66 72 65 65 77 6f 72 6b 7a [0-08] 2e 64 6c 6c } //1
		$a_00_5 = {70 6c 61 79 70 69 63 6b 6c 65 62 61 72 33 32 2e 64 6c 6c } //1 playpicklebar32.dll
		$a_00_6 = {6c 69 76 69 6e 67 70 6c 61 79 6c 69 62 33 32 2e 64 6c 6c } //1 livingplaylib32.dll
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=111
 
}
rule _#Adware_Win32_GameVance_26{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff ff 41 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 56 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 74 } //1
		$a_03_1 = {ff ff 43 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 46 } //1
		$a_03_2 = {43 00 00 00 66 89 95 ?? fc ff ff b8 3a 00 00 00 66 89 85 ?? fc ff ff b9 5c 00 00 00 } //1
		$a_03_3 = {54 49 00 00 66 89 85 ?? fc ff ff b9 54 59 00 00 66 89 8d ?? fc ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_27{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff 54 49 54 49 [0-15] 3e 81 bd ?? ?? ff ff 54 49 54 49 [0-15] 3e 81 bd ?? ?? ff ff 58 30 58 30 } //10
		$a_03_1 = {ff ff 4c 49 4c 49 [0-25] 3e 81 bd ?? ?? ff ff 57 57 57 57 [0-25] 3e 81 bd ?? ?? ff ff 54 59 54 59 } //10
		$a_03_2 = {ff ff 54 49 54 49 77 35 81 bd ?? ?? ff ff 54 49 54 49 0f 84 ?? 00 00 00 81 bd ?? ?? ff ff 58 30 58 30 0f 84 ?? ?? 00 00 81 bd ?? ?? ff ff 4c 49 4c 49 0f 84 ?? ?? 00 00 e9 ?? ?? 00 00 81 bd ?? ?? ff ff 57 57 57 57 74 15 81 bd ?? ?? ff ff 54 59 54 59 0f 84 ?? 00 00 00 e9 ?? ?? 00 00 81 bd ?? ?? ff ff 57 57 57 00 } //20
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*20) >=20
 
}
rule _#Adware_Win32_GameVance_28{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {fc ab 83 c1 0f eb 90 14 83 e1 0f eb 90 14 3e 8b 94 8d ?? ?? ff ff eb 90 14 52 } //2
		$a_03_1 = {b9 fb ff ff ff eb 90 14 f7 d9 eb 90 14 3e 8b 85 ?? ?? ff ff eb 90 14 d3 e0 eb 90 14 25 } //2
		$a_03_2 = {ff ff 02 00 00 00 eb 90 14 3e c7 85 ?? ?? ff ff 00 00 00 00 eb 90 14 eb 90 14 3e 81 bd ?? ?? ff ff 8c 00 00 00 eb } //1
		$a_03_3 = {3e c7 45 fc 02 00 00 00 eb 90 14 3e c7 45 f8 00 00 00 00 eb 90 14 eb 90 14 3e 81 7d f8 ?? 00 00 00 eb } //1
		$a_03_4 = {ff ff 47 eb 06 ?? ?? ?? ?? ?? ?? 3e c6 85 ?? ?? ff ff 65 eb 90 14 3e c6 85 ?? ?? ff ff 74 eb 90 14 3e c6 85 ?? ?? ff ff 4d eb 90 14 3e c6 85 ?? ?? ff ff 6f eb 90 14 3e c6 85 ?? ?? ff ff 64 eb } //2
		$a_03_5 = {ff ff 47 eb 06 ?? ?? ?? ?? ?? ?? 3e c6 85 ?? ?? ff ff 65 eb 90 14 3e c6 85 ?? ?? ff ff 74 eb 90 14 3e c6 85 ?? ?? ff ff 4c eb 90 14 3e c6 85 ?? ?? ff ff 61 eb 90 14 3e c6 85 ?? ?? ff ff 73 eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2) >=3
 
}
rule _#Adware_Win32_GameVance_29{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0c 00 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 72 6f 63 6b 73 74 61 72 00 } //10
		$a_01_1 = {63 6c 69 65 6e 74 5f 69 6e 73 74 61 6c 6c 5f 6d 74 78 5f 41 42 43 44 00 } //10 汣敩瑮楟獮慴汬浟硴䅟䍂D
		$a_01_2 = {67 72 73 63 6c 61 73 73 00 } //10
		$a_03_3 = {5f 69 6e 73 74 61 6c 6c 65 72 5f 6d 74 78 90 09 03 00 (6d 6d 67|6c 70 67) } //10
		$a_03_4 = {67 61 6d 65 76 61 6e 63 65 2e (63 6f 6d|6e 65 74) } //10
		$a_01_5 = {42 46 47 41 4d 45 55 52 4c 5f 46 41 49 4c } //10 BFGAMEURL_FAIL
		$a_01_6 = {4e 6f 4e 6f 49 74 73 4e 6f 74 48 65 72 65 } //10 NoNoItsNotHere
		$a_03_7 = {6c 6c 65 72 5f 6d 74 78 00 00 00 00 ?? ?? ?? 5f 69 6e 73 74 61 } //1
		$a_03_8 = {70 61 67 65 73 2e 6c 69 76 69 6e 67 70 6c 61 79 2e 63 6f 6d 2f 61 6a 2f (62 75 6e 64|69 6e 73 74) 2e 70 68 70 00 } //1
		$a_01_9 = {70 6c 61 79 70 69 63 6b 6c 65 77 6e 61 6d 65 00 70 6c 61 79 70 69 63 6b 6c 65 63 6c 61 73 73 00 } //1 汰祡楰正敬湷浡e汰祡楰正敬汣獡s
		$a_01_10 = {47 41 4d 2d 53 52 53 2d 54 33 } //10 GAM-SRS-T3
		$a_01_11 = {6c 70 6c 61 79 63 6c 61 73 73 00 00 6c 70 6c 61 79 77 6e 61 6d 65 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*10+(#a_01_11  & 1)*1) >=31
 
}
rule _#Adware_Win32_GameVance_30{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 85 d9 fe ff ff 41 [0-10] c6 85 da fe ff ff 63 [0-10] c6 85 db fe ff ff 71 [0-10] c6 85 dc fe ff ff 75 [0-10] c6 85 dd fe ff ff 69 [0-10] c6 85 de fe ff ff 72 [0-10] c6 85 df fe ff ff 65 [0-10] c6 85 e0 fe ff ff 43 } //1
		$a_03_1 = {c6 85 5c ff ff ff 43 [0-10] c6 85 5d ff ff ff 72 [0-10] c6 85 5e ff ff ff 79 [0-10] c6 85 5f ff ff ff 70 [0-10] c6 85 60 ff ff ff 74 [0-10] c6 85 61 ff ff ff 44 [0-10] c6 85 62 ff ff ff 65 [0-10] c6 85 63 ff ff ff 73 } //1
		$a_03_2 = {c6 85 1c fe ff ff 48 [0-10] c6 85 1d fe ff ff 61 [0-10] c6 85 1e fe ff ff 73 [0-10] c6 85 1f fe ff ff 68 [0-10] c6 85 20 fe ff ff 50 [0-10] c6 85 21 fe ff ff 61 [0-10] c6 85 22 fe ff ff 72 [0-10] c6 85 23 fe ff ff 61 [0-10] c6 85 24 fe ff ff 6d } //1
		$a_03_3 = {c6 85 a1 fe ff ff 50 [0-11] c6 85 a2 fe ff ff 72 [0-11] c6 85 a3 fe ff ff 69 [0-11] c6 85 a4 fe ff ff 6f [0-11] c6 85 a5 fe ff ff 72 [0-11] c6 85 a6 fe ff ff 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_31{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 70 69 63 70 6c 61 79 } //1 epicplay
		$a_01_1 = {66 72 65 65 77 6f 72 6b 7a } //1 freeworkz
		$a_01_2 = {72 69 76 61 6c 67 61 6d 69 6e 67 } //1 rivalgaming
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#Adware_Win32_GameVance_32{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 77 74 6c 49 45 2e 64 6c 6c } //1 fwtlIE.dll
		$a_01_1 = {46 72 65 65 77 6f 72 6b 7a 20 54 6f 75 72 6e 61 6d 65 6e 74 } //1 Freeworkz Tournament
		$a_01_2 = {66 72 65 65 77 6f 72 6b 7a 2e 63 6f 6d } //1 freeworkz.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_33{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 61 74 61 4c 6f 77 5c 6c 70 6c 61 79 74 6c } //1 AppDataLow\lplaytl
		$a_01_1 = {6c 70 74 6c 66 2e 64 6c 6c } //1 lptlf.dll
		$a_01_2 = {4c 69 76 69 6e 67 50 6c 61 79 20 54 6f 75 72 6e 61 6d 65 6e 74 } //1 LivingPlay Tournament
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_34{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 70 69 63 50 6c 61 79 47 61 6d 65 73 2e 64 6c 6c } //1 epicPlayGames.dll
		$a_01_1 = {65 70 69 63 5f 70 6c 61 79 5f 6d 74 78 5f 63 66 67 74 68 72 } //1 epic_play_mtx_cfgthr
		$a_01_2 = {63 6c 69 65 6e 74 5f 75 70 64 61 74 65 2e 65 78 65 } //1 client_update.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_35{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 69 76 61 6c 47 61 6d 69 6e 67 44 61 74 61 } //1 RivalGamingData
		$a_01_1 = {52 69 76 61 6c 47 61 6d 69 6e 67 2e 78 70 74 } //1 RivalGaming.xpt
		$a_01_2 = {72 69 76 61 6c 67 61 6d 69 6e 67 5f 73 65 74 75 70 5f 73 74 61 72 74 65 64 } //1 rivalgaming_setup_started
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_36{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 57 6f 72 6b 7a 2e 44 4c 4c } //1 FreeWorkz.DLL
		$a_01_1 = {6c 61 50 6c 75 67 69 6e 73 5c 6e 70 46 72 65 65 57 6f 72 6b 7a 44 69 73 70 6c 61 79 } //1 laPlugins\npFreeWorkzDisplay
		$a_01_2 = {66 72 65 65 77 6f 72 6b 7a 5f 75 70 64 61 74 65 2e 65 78 65 } //1 freeworkz_update.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_GameVance_37{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 67 61 6d 65 76 61 6e 63 65 2e 63 6f 6d } //1 .gamevance.com
		$a_01_1 = {61 72 73 67 72 73 5f 77 6d 5f } //1 arsgrs_wm_
		$a_01_2 = {5c 47 61 6d 65 56 61 6e 63 65 5c 50 6f 70 75 70 43 6c 69 65 6e 74 } //1 \GameVance\PopupClient
		$a_01_3 = {46 69 6e 64 42 72 6f 77 73 65 72 57 69 6e 64 6f 77 } //1 FindBrowserWindow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#Adware_Win32_GameVance_38{
	meta:
		description = "!#Adware:Win32/GameVance,SIGNATURE_TYPE_PEHSTR,03 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 70 69 63 50 6c 61 79 20 47 61 6d 65 73 20 45 78 74 65 6e 73 69 6f 6e } //1 EpicPlay Games Extension
		$a_01_1 = {65 70 69 63 50 6c 61 79 47 61 6d 65 73 2e 64 6c 6c } //1 epicPlayGames.dll
		$a_01_2 = {41 70 70 44 61 74 61 4c 6f 77 5c 65 50 6c 61 79 43 6f 6e 66 } //1 AppDataLow\ePlayConf
		$a_01_3 = {65 70 69 63 70 6c 61 79 2e 63 6f 6d } //1 epicplay.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}