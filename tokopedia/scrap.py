from tokped import *
from argparse import ArgumentParser

if __name__ == '__main__':
	try:
		parser = ArgumentParser(description='Tokopedia Downloader URL')

		parser.add_argument('-T', '--toko'   , dest='toko'   , type=str, help='nama toko yang ada di tokopedia')
		parser.add_argument('-F', '--file'   , dest='file'   , type=int, help='simpan file ke (1: json / 2: csv)')
		parser.add_argument('-D', '--data'   , dest='data'   , type=int, help='tampilkan data (0: false / 1: true)')

		args 	= parser.parse_args()
		
		if args.toko is None:
			system("cls||clear")
			print("\n [#] Scraper produk yang ada di toko dari tokopedia")
			print("  |")
			print("  +-[>] nama toko      (-T, --toko)")
			print("     |")
			print("    [>] tipe file      (-F, --file): 1. json ")
			print("     |                               2. csv  (default)")
			print("     |")
			print("    [>] tampilkan data (-D, --data): 0. jangan tampilkan data (default)")
			print("                                     1. tampilkan data")
			print("")
			print(" [>] Contoh penggunaan: scrap.py --toko syauqqii --file 1 --data 1")
			exit(0)
		elif args.file is None:
			args.file = 2
		elif args.data is None:
			args.data = 0

		process = tokopedia(args.toko, args.data, args.file)
	except KeyboardInterrupt:
    		exit(0)
