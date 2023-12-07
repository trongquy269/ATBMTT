# Nguyễn Trọng Quý
# MSSV: B2017000
# STT: 37

from tkinter import *
from tkinter import filedialog
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import tkinter as tk
import base64

class ENCRYPT_AFFINE(tk.Toplevel):
	def __init__(self, parent):
		self.parent = parent
		Toplevel.__init__(self)

		self.title("Chương trình mã hóa đối xứng")
		self.geometry("900x180")

		self.heading = Label(self, text="CHƯƠNG TRÌNH DEMO", font=("Arial Bold", 20))
		self.heading.grid(column=1, row=1)

		self.subheading = Label(self, text="MẬT MÃ AFFINE", font=("Arial Bold", 15))
		self.subheading.grid(column=0, row=2)

		self.plaintext_lbl = Label(self, text="Văn bản gốc", font=("Arial Bold", 14))
		self.plaintext_lbl.grid(column=0, row=3)
		self.plaintext_entry = Entry(self, width=30)
		self.plaintext_entry.grid(column=1, row=3)

		self.key_lbl = Label(self, text="Cặp khóa", font=("Arial Bold", 14))
		self.key_lbl.grid(column=2, row=3)
		self.key_st_entry = Entry(self, width=5)
		self.key_st_entry.grid(column=3, row=3)
		self.key_nd_entry = Entry(self, width=5)
		self.key_nd_entry.grid(column=4, row=3)

		self.encrypt_btn = Button(self, text="Mã hóa", command=self.encrypt)
		self.encrypt_btn.grid(column=5, row=3)

		self.cipher_text_lbl = Label(self, text="Văn bản được mã hóa", font=("Arial Bold", 14))
		self.cipher_text_lbl.grid(column=0, row=4)
		self.cipher_text_entry = Entry(self, width=30)
		self.cipher_text_entry.grid(column=1, row=4)

		self.decrypt_btn = Button(self, text="Giải mã", command=self.decrypt)
		self.decrypt_btn.grid(column=2, row=4)

		self.decrypt_text_entry = Entry(self, width=30)
		self.decrypt_text_entry.grid(column=3, row=4)

		self.exit_btn = Button(self, text="Thoát", command=self.destroy)
		self.exit_btn.grid(column=5, row=4)

	def char2num(self, c):
		if ord(c) == 32:
			return 52
		elif ord(c) >= 97:
			return ord(c) - 71
		else:
			return ord(c) - 65
		
	def num2char(self, n):
		if n == 52:
			return chr(32)
		elif n >= 26:
			return chr(n + 71)
		else:
			return chr(n + 65)
		
	def xgcd(self, a, m):
		temp = m
		x0, x1, y0, y1 = 1, 0, 0, 1
		while m != 0:
			q, a, m = a // m, m, a % m
			x0, x1 = x1, x0 - q * x1
			y0, y1 = y1, y0 - q * y1
		if x0 < 0:
			x0 += temp

		return x0
	
	def encrypt(self):
		plaintext = self.plaintext_entry.get()
		key_st = int(self.key_st_entry.get())
		key_nd = int(self.key_nd_entry.get())
		m = 53
		cipher_text = ""
		
		for c in plaintext:
			cipher_text += self.num2char((key_st * self.char2num(c) + key_nd) % m)

		self.cipher_text_entry.delete(0, END)
		self.cipher_text_entry.insert(INSERT, cipher_text)

	def decrypt(self):
		cipher_text = self.cipher_text_entry.get()
		key_st = int(self.key_st_entry.get())
		key_nd = int(self.key_nd_entry.get())
		m = 53
		plaintext = ""
		key_st_inv = self.xgcd(key_st, m)

		for c in cipher_text:
			plaintext += self.num2char((key_st_inv * (self.char2num(c) - key_nd)) % m)

		self.decrypt_text_entry.delete(0, END)
		self.decrypt_text_entry.insert(INSERT, plaintext)

# Padding
def pad(s):
	# Add padding to make input a multiple of 8 bytes
	return s + (8 - len(s) % 8) * chr(8 - len(s) % 8)

# Unpadding
def unpad(s):
	# Remove padding
	return s[:-ord(s[len(s) - 1:])]

# Create DES window
class ENCRYPT_DES(tk.Toplevel):
	def __init__(self, parent):
		self.parent = parent
		Toplevel.__init__(self)
		self.title("Chương trình mã hóa đối xứng")
		self.geometry("800x270")
		self.heading = Label(self, text="CHƯƠNG TRÌNH DEMO", font=("Arial Bold", 20))
		self.heading.grid(column=1, row=1)

		self.subheading = Label(self, text="MẬT MÃ ĐỐI XỨNG", font=("Arial Bold", 15))
		self.subheading.grid(column=1, row=2)

		self.plaintext_lbl = Label(self, text="Văn bản gốc", font=("Arial Bold", 14))
		self.plaintext_lbl.grid(column=0, row=4)
		self.plaintext_entry = Entry(self, width=100)
		self.plaintext_entry.grid(column=1, row=4)

		self.key_lbl = Label(self, text="Khóa", font=("Arial Bold", 14))
		self.key_lbl.grid(column=0, row=5)
		self.key_entry = Entry(self, width=100)
		self.key_entry.grid(column=1, row=5)

		self.cipher_text_lbl = Label(self, text="Văn bản được mã hóa", font=("Arial Bold", 14))
		self.cipher_text_lbl.grid(column=0, row=6)
		self.cipher_text_entry = Entry(self, width=100)
		self.cipher_text_entry.grid(column=1, row=6)

		self.decrypt_text_lbl = Label(self, text="Văn bản được giải mã", font=("Arial Bold", 14))
		self.decrypt_text_lbl.grid(column=0, row=7)
		self.decrypt_text_entry = Entry(self, width=100)
		self.decrypt_text_entry.grid(column=1, row=7)

		self.encrypt_btn = Button(self, text="Mã hóa", command=self.encrypt)
		self.encrypt_btn.grid(column=1, row=9)

		self.decrypt_btn = Button(self, text="Giải mã", command=self.decrypt)
		self.decrypt_btn.grid(column=1, row=10)

		self.exit_btn = Button(self, text="Thoát", command=self.destroy)
		self.exit_btn.grid(column=1, row=11)

	def encrypt(self):
		plaintext = pad(self.plaintext_entry.get()).encode('utf-8')
		key = pad(self.key_entry.get()).encode('utf-8')
		cipher = DES.new(key, DES.MODE_ECB)
		encrypt_text = cipher.encrypt(plaintext)
		encrypt_text = base64.b64encode(encrypt_text)

		self.cipher_text_entry.delete(0, END)
		self.cipher_text_entry.insert(INSERT, encrypt_text)

	def decrypt(self):
		encrypt_text = self.cipher_text_entry.get()
		encrypt_text = base64.b64decode(encrypt_text)
		key = pad(self.key_entry.get()).encode('utf-8')
		cipher = DES.new(key, DES.MODE_ECB)
		decrypt_text = unpad(cipher.decrypt(encrypt_text))

		self.decrypt_text_entry.delete(0, END)
		self.decrypt_text_entry.insert(INSERT, decrypt_text)

class ENCRYPT_RSA(tk.Toplevel):
	def __init__(self, parent):
		self.parent = parent
		Toplevel.__init__(self)

		self.title("Welcome to Demo An Toàn Bảo Mật Thông Tin")
		self.geometry('800x450')

		self.heading = Label(self, text="CHƯƠNG TRÌNH DEMO", font=("Arial Bold", 20))
		self.heading.grid(column=1, row=0)
		self.subheading = Label(self, text="MẬT MÃ BẤT ĐỐI XỨNG RSA", font=("Arial Bold", 15))
		self.subheading.grid(column=1, row=1)

		self.plaintext_label = Label(self, text="Văn bản gốc", font=("Arial Bold", 10))
		self.plaintext_label.grid(column=0, row=2)
		self.plaintext_input = Text(self, height=1, width=80)
		self.plaintext_input.grid(column=1, row=2)

		self.encrypt_label = Label(self, text="Văn bản được mã hóa", font=("Arial Bold", 10))
		self.encrypt_label.grid(column=0, row=3)
		self.encrypt_input = Text(self, height=1, width=80)
		self.encrypt_input.grid(column=1, row=3)

		self.decrypt_label = Label(self, text="Văn bản được giải mã", font=("Arial Bold", 10))
		self.decrypt_label.grid(column=0, row=4)
		self.decrypt_input = Text(self, height=1, width=80)
		self.decrypt_input.grid(column=1, row=4)

		self.private_key_label = Label(self, text="Khóa bí mật", font=("Arial Bold", 10))
		self.private_key_label.grid(column=0, row=5)
		self.private_key_input = Text(self, height=6, width=80)
		self.private_key_input.grid(column=1, row=5)

		self.public_key_label = Label(self, text="Khóa công khai", font=("Arial Bold", 10))
		self.public_key_label.grid(column=0, row=6)
		self.public_key_input = Text(self, height=6, width=80)
		self.public_key_input.grid(column=1, row=6)

		# Create button
		self.create_key_button = Button(self, text="Tạo khóa", font=("Arial Bold", 10), cursor="hand2", command=self.generate_key)
		self.create_key_button.grid(column=1, row=7)

		self.encrypt_button = Button(self, text="Mã hóa", font=("Arial Bold", 10), cursor="hand2", command=self.encrypt_rsa)
		self.encrypt_button.grid(column=1, row=8)

		self.decrypt_button = Button(self, text="Giải mã", font=("Arial Bold", 10), cursor="hand2", command=self.decrypt_rsa)
		self.decrypt_button.grid(column=1, row=9)

		self.exit_button = Button(self, text="Thoát", font=("Arial Bold", 10), cursor="hand2", command=self.destroy)
		self.exit_button.grid(column=1, row=10)

	def save_file(self, data, _mode, _title, _filetypes, _defaultextension):
		file = filedialog.asksaveasfile(mode=_mode, title=_title, filetypes=_filetypes, defaultextension=_defaultextension)

		if file is None: return
		file.write(data)
		file.close()

	def generate_key(self):
		key = RSA.generate(1024)
		private_key = self.save_file(key.export_key('PEM'), 'wb', 'Lưu khóa cá nhân', (("All files", "*.*"), ("PEM files", "*.pem")), '.pem')
		public_key = self.save_file(key.publickey().export_key('PEM'), 'wb', 'Lưu khóa công khai', (("All files", "*.*"), ("PEM files", "*.pem")), '.pem')

		self.private_key_input.delete('1.0', END)
		self.private_key_input.insert(END, key.export_key('PEM'))
		self.public_key_input.delete('1.0', END)
		self.public_key_input.insert(END, key.publickey().export_key('PEM'))

	def get_key (self, key_style):
		filename = filedialog.askopenfilename(initialdir="E:/Workspace/Python/ATBMTT/TH5/", title='Open' + key_style, filetypes=(("All files", "*.*"), ("PEM files", "*.pem")))

		if filename is None: return
		file = open(filename, 'rb')
		key = file.read()
		file.close()

		return RSA.importKey(key)

	def encrypt_rsa (self):
		plaintext = self.plaintext_input.get("1.0", END).encode('utf-8')
		public_key = self.get_key('Public key')
		cipher_text = PKCS1_v1_5.new(public_key).encrypt(plaintext)
		cipher_text = base64.b64encode(cipher_text).decode('utf-8')
		
		self.encrypt_input.delete('1.0', END)
		self.encrypt_input.insert(INSERT, cipher_text)

	def decrypt_rsa (self):
		cipher_text = self.encrypt_input.get("1.0", END).encode('utf-8')
		cipher_text = base64.b64decode(cipher_text)
		private_key = self.get_key('Private key')
		plaintext_bytes = PKCS1_v1_5.new(private_key).decrypt(cipher_text, None)
		plaintext = plaintext_bytes.decode('utf-8')

		self.decrypt_input.delete('1.0', END)
		self.decrypt_input.insert(INSERT, plaintext)


# Create main window
class MainWindow(tk.Frame):
	def __init__(self, parent):
		self.parent = parent
		tk.Frame.__init__(self)

		self.encrypt_Affine = Button(text="Mã hóa Affine", font=("Times New Roman", 11), command=self.affine)
		self.encrypt_Affine.pack()

		self.encrypt_DES = Button(text="Mã hóa DES", font=("Times New Roman", 11), command=self.des)
		self.encrypt_DES.pack()

		self.encrypt_RSA = Button(text="Mã hóa RSA", font=("Times New Roman", 11),command=self.rsa)
		self.encrypt_RSA.pack()

		self.exit = Button(text="Thoát", font=("Times New Roman", 11), command=self.quit)
		self.exit.pack()

	def affine(self):
		ENCRYPT_AFFINE(self)

	def des(self):
		ENCRYPT_DES(self)

	def rsa(self):
		ENCRYPT_RSA(self)

def main():
	window = tk.Tk()
	window.title("Chương trình chính")
	window.geometry("300x200")
	MainWindow(window)
	window.mainloop()

main()