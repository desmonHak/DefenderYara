
rule Trojan_Win32_DarkCloud_AMTB{
	meta:
		description = "Trojan:Win32/DarkCloud!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\User Data\Default\Login Data  2
		$a_80_1 = {4e 61 6d 65 20 6f 6e 20 43 61 72 64 3a } //Name on Card:  2
		$a_80_2 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT origin_url, username_value, password_value FROM logins  2
		$a_80_3 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards  2
		$a_80_4 = {53 45 4c 45 43 54 20 68 6f 73 74 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT hostname, encryptedUsername, encryptedPassword  FROM moz_logins  2
		$a_80_5 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 44 41 52 4b 43 4c 4f 55 44 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d } //===============DARKCLOUD===============  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=12
 
}