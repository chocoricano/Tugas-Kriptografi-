import re
import json
from requests import get, post
from pandas import DataFrame
from os import mkdir, path, system, name
from bs4 import BeautifulSoup as bsoup

class tokopedia():
	def __init__(self, nama_toko, tampil=0, simpan=1):
		self.link_toko	= f'https://tokopedia.com/{nama_toko}'
		self.nama_toko	= nama_toko
		self.tampil 	= tampil
		self.simpan	= simpan
		self.header	= {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0'}
		self.dapatkanID()

	def dapatkanID(self):
		try:
			req 	= post(self.link_toko, headers=self.header, timeout=3.000)

			system("cls||clear")

			print('\n [#] Alat untuk mengambil informasi produk yang ada ditokopedia!')
			print('  |')
			print(f'  +-[>] Toko : {self.link_toko}')
			print('\n [#] Hasil')
			print('  |')

			if req.status_code == 200:
				proses = bsoup(req.text, 'html.parser')
				script_element = proses.find_all('script', type='text/javascript')
				script_content = script_element[3].string
				pattern = r'\{\\\"shop_ids\\\":\[(\d+)\]\}'
				matches = re.findall(pattern, script_content)
				if matches:
					self.ID_toko = matches[0]
					print(f'  +-[>] Toko ditemukan <Response Code [{req.status_code}]>')
					print(f'    [>] ID Toko : {self.ID_toko}')
					self.dapatkanData()
				else:
					print(f'  +-[!] ERROR: Tidak dapat mendapatkan ID Toko')
			else:
				print(f'  +-[!] Toko tidak ditemukan <Response Code [{req.status_code}]>')
		except:
			print(f'  +-[!] Toko tidak valid <Response Code [{req.status_code}]>')

	def dapatkanData(self):
		link_json	= f'https://ace.tokopedia.com/search/product/v3?shop_id={self.ID_toko}&rows=80&start=0&full_domain=www.tokopedia.com&scheme=https&device=desktop&source=shop_product'
		request 	= get(link_json, headers=self.header)
		self.hasil	= request.json()

		if not path.isdir(self.nama_toko):
			mkdir(self.nama_toko)

		with open(f'{self.nama_toko}/{self.nama_toko}_[detail].json', 'w') as file:
			json.dump(self.hasil, file)

		self.tampilkanData()

	def tampilkanData(self):
		self.jumlah_produk	= len(self.hasil['data']['products'])
		self.semua_produk	= []

		print(f'    [>] Total   : {self.jumlah_produk} produk')

		for num, i in enumerate(self.hasil['data']['products']):
			price = f"Rp {(i['price'])[2:]}"

			if self.tampil == 1:
				if num < 10:
					print(f"\n [00{num+1}] ===========================================================================================================================================")
					print(f"   Nama     : {i['name']}")
					print(f"   Harga    : {price}")
					print(f"   Kategori : {i['category_name']}")
					print(f"   Link     : {i['url']}")
				elif num < 100:
					print(f"\n [0{num+1}] ===========================================================================================================================================")
					print(f"   Nama     : {i['name']}")
					print(f"   Harga    : {price}")
					print(f"   Kategori : {i['category_name']}")
					print(f"   Link     : {i['url']}")
				elif num < 1000:
					print(f"\n [{num+1}] ===========================================================================================================================================")
					print(f"   Nama     : {i['name']}")
					print(f"   Harga    : {price}")
					print(f"   Kategori : {i['category_name']}")
					print(f"   Link     : {i['url']}")

				self.semua_produk.append([
					i['name'],
					price,
					i['url'],
					i['image_url'],
					i['category_name']
				])
			else:
				self.semua_produk.append([
					i['name'],
					price,
					i['url'],
					i['image_url'],
					i['category_name']
				])

		self.simpanProduk()

	def simpanProduk(self):
		if self.simpan == 1:
			data = []
			for i in self.semua_produk:
				data += [{'name':i[0], 'price':i[1], 'url':i[2], 'image_url':i[3],'category_name':i[4]}]

			with open(f'{self.nama_toko}/{self.nama_toko}_[produk].json', 'w') as file:
				json.dump(data, file)

		elif self.simpan == 2:
			try:
				df = DataFrame(self.semua_produk, columns=['name', 'price', 'url', 'image_url', 'category_name'])
				df.to_csv(f'{self.nama_toko}/{self.nama_toko}_[produk].csv', index=False)
			except:
				logging.exception('\n [!] ERROR: Tidak bisa menyimpan ke CSV!')

		print('\n [#] File berhasil disimpan')
		print('  |')
		print(f'  +-[#] {self.nama_toko}/')
		print('     |')
		print(f'     +-[>] {self.nama_toko}_[detail].json')
		if self.simpan == 1:
			print(f'           {self.nama_toko}_[produk].json')
		else:
			print(f'           {self.nama_toko}_[produk].csv')
