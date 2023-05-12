# Tkinter kütüphanesini içe aktar
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

# hashlib kütüphanesini içe aktar
import hashlib

# Uygulama arayüzü için bir pencere oluştur
window = tk.Tk()
window.title("Dosya Hash Uygulaması")
window.geometry("600x400")

# Dosya seçme fonksiyonu
def select_file():
    # Kullanıcıdan bir dosya seçmesini iste
    file_path = filedialog.askopenfilename()
    # Seçilen dosyanın yolunu ekrana yaz
    file_label.config(text=file_path)
    # Seçilen dosyanın hash değerlerini hesapla ve ekrana yaz
    calculate_hashes(file_path)

# Hash değerlerini hesaplama fonksiyonu
def calculate_hashes(file_path):
    # Dosyayı ikili modda aç
    with open(file_path, "rb") as f:
        # Dosyanın içeriğini oku
        data = f.read()
        # MD5 hash değerini hesapla ve ekrana yaz
        md5_hash = hashlib.md5(data).hexdigest()
        md5_label.config(text=md5_hash)
        # SHA1 hash değerini hesapla ve ekrana yaz
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha1_label.config(text=sha1_hash)
        # SHA256 hash değerini hesapla ve ekrana yaz
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha256_label.config(text=sha256_hash)
        # SHA512 hash değerini hesapla ve ekrana yaz
        sha512_hash = hashlib.sha512(data).hexdigest()
        sha512_label.config(text=sha512_hash)
        # RIPEMD-160 hash değerini hesapla ve ekrana yaz
        ripemd160_hash = hashlib.new("ripemd160", data).hexdigest()
        ripemd160_label.config(text=ripemd160_hash)

# Hash karşılaştırma fonksiyonu
def compare_hashes():
    # Kullanıcının girdiği hash değerini al
    input_hash = entry.get()
    # Eğer girdi boşsa uyarı ver
    if not input_hash:
        messagebox.showwarning("Uyarı", "Lütfen bir hash değeri girin.")
        return
    # Eğer girdi 32 karakterliyse MD5 ile karşılaştır
    if len(input_hash) == 32:
        file_hash = md5_label.cget("text")
    # Eğer girdi 40 karakterliyse SHA1 ile karşılaştır
    elif len(input_hash) == 40:
        file_hash = sha1_label.cget("text")
    # Eğer girdi 64 karakterliyse SHA256 ile karşılaştır
    elif len(input_hash) == 64:
        file_hash = sha256_label.cget("text")
    # Eğer girdi 128 karakterliyse SHA512 ile karşılaştır
    elif len(input_hash) == 128:
        file_hash = sha512_label.cget("text")
    # Eğer girdi 40 karakterliyse RIPEMD-160 ile karşılaştır
    elif len(input_hash) == 40:
        file_hash = ripemd160_label.cget("text")
    # Eğer girdi geçerli bir hash uzunluğunda değilse uyarı ver
    else:
        messagebox.showerror("Hata", "Geçersiz hash uzunluğu.")
        return
    # Girdi ile dosya hash değerini karşılaştır
    if input_hash == file_hash:
        # Eğer eşitse doğrulama başarılı mesajı ver
        messagebox.showinfo("Doğrulama", "Hash değerleri eşleşiyor. Dosya doğrulanmıştır.")
    else:
        # Eğer eşit değilse doğrulama başarısız mesajı ver
        messagebox.showerror("Doğrulama", "Hash değerleri eşleşmiyor. Dosya doğrulanamamıştır.")

# Arayüzdeki widgetleri oluştur
file_label = tk.Label(window, text="Dosya seçmek için butona tıklayın.")
file_button = tk.Button(window, text="Dosya Seç", command=select_file)
md5_label = tk.Label(window, text="MD5: ")
sha1_label = tk.Label(window, text="SHA1: ")
sha256_label = tk.Label(window, text="SHA256: ")
sha512_label = tk.Label(window, text="SHA512: ")
ripemd160_label = tk.Label(window, text="RIPEMD-160: ")
entry_label = tk.Label(window, text="Hash değeri girin:")
entry = tk.Entry(window)
compare_button = tk.Button(window, text="Karşılaştır", command=compare_hashes)

# Arayüzdeki widgetleri yerleştir
file_label.pack(pady=10)
file_button.pack(pady=10)
md5_label.pack(pady=10)
sha1_label.pack(pady=10)
sha256_label.pack(pady=10)
sha512_label.pack(pady=10)
ripemd160_label.pack(pady=10)
entry_label.pack(pady=10)
entry.pack(pady=10)
compare_button.pack(pady=10)

# Pencereyi göster
window.mainloop()
