from tokped import *

def main():
	if name == "nt":
		system('title Tokopedia . code by https://github.com/syauqqii (syauqi)')
		system('mode con: cols=163 lines=30')
	else:
		pass

	system('@cls||clear')

	print('\n [#] Alat untuk mengambil informasi produk yang ada ditokopedia!')
	print('  |')
	input_nama_toko = input('  +-[>] Masukkan nama toko : https://tokopedia.com/')

	print('\n [#] Format file :')
	print('  |')
	print('  | [1] .json')
	print('  | [2] .csv')
	print('  |')

	while(True):
		simpan_file = input(' [>] Pilih : (1/2) ')
		
		try:
			simpan_file = int(simpan_file)
		except ValueError:
			system('@cls||clear')

			print('\n [#] Alat untuk mengambil informasi toko yang ada di tokopedia!')
			print('  |')
			print(f'  +-[>] Masukkan nama toko : https://tokopedia.com/{input_nama_toko}')

			print('\n [#] Format file :')
			print('  |')
			print('  | [1] .json')
			print('  | [2] .csv')
			print('  |')
			continue

		if 1 <= simpan_file <= 2:
			break;
		else:
			system('@cls||clear')

			print('\n [#] Alat untuk mengambil informasi toko yang ada di tokopedia!')
			print('  |')
			print(f'  +-[>] Masukkan nama toko : https://tokopedia.com/{input_nama_toko}')

			print('\n [#] Format file :')
			print('  |')
			print('  | [1] .json')
			print('  | [2] .csv')
			print('  |')
			continue;

	print('\n [#] Tampilkan (dump) data di CLI (command line interface) :')
	print('  |')
	print('  | [1] Ya')
	print('  | [2] Tidak')
	print('  |')

	while(True):
		tampil = input(' [>] Pilih : (1/2) ')
		
		try:
			tampil = int(tampil)
		except ValueError:
			system('@cls||clear')

			print('\n [#] Alat untuk mengambil informasi toko yang ada di tokopedia!')
			print('  |')
			print(f'  +-[>] Masukkan nama toko : https://tokopedia.com/{input_nama_toko}')

			print('\n [#] Format file :')
			print('  |')
			print('  | [1] .json')
			print('  | [2] .csv')
			print('  |')
			print(f' [>] Pilih : (1/2) {simpan_file}')

			print('\n [#] Tampilkan (dump) data di CLI (command line interface) :')
			print('  |')
			print('  | [1] Ya')
			print('  | [2] Tidak')
			print('  |')
			continue

		if 1 <= tampil <= 2:
			break;
		else:
			system('@cls||clear')

			print('\n [#] Alat untuk mengambil informasi toko yang ada di tokopedia!')
			print('  |')
			print(f'  +-[>] Masukkan nama toko : https://tokopedia.com/{input_nama_toko}')

			print('\n [#] Format file :')
			print('  |')
			print('  | [1] .json')
			print('  | [2] .csv')
			print('  |')
			print(f' [>] Pilih : (1/2) {simpan_file}')

			print('\n [#] Tampilkan (dump) data di CLI (command line interface) :')
			print('  |')
			print('  | [1] Ya')
			print('  | [2] Tidak')
			print('  |')
			continue;

	proses = tokopedia(str(input_nama_toko), int(tampil), int(simpan_file))

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print('\n\n [>] Good Bye!\n')
		exit(0)
