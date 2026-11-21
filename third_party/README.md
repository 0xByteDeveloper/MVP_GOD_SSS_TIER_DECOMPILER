# third_party — Motor Kütüphaneleri

## Linux (hazır)
Bu depoda Linux x64 paylaşımlı kütüphaneleri mevcuttur:
- `lib/capstone.so` (+ .so.5)  — Capstone 5.0.7 (BSD-3)
- `lib/unicorn.so` (+ .so.2)   — Unicorn 2.1.4 (GPLv2)
- `lib/keystone.so` (+ .so.0)  — Keystone 0.9.2 (GPLv2)
Başlıklar `include/` altındadır (ilgili sürüm tag'lerinden).

## Windows
Aşağıdaki dosyaları `lib/` klasörüne koyun (dll'ler derleme sonrası bin/
yanına otomatik kopyalanır):

| Dosya | Kaynak |
|---|---|
| `capstone.lib` (+ `capstone.dll`) | https://github.com/capstone-engine/capstone/releases |
| `unicorn.lib` (+ `unicorn.dll`) | https://github.com/unicorn-engine/unicorn/releases |
| `keystone.lib` (+ `keystone.dll`) | https://github.com/keystone-engine/keystone/releases |

Alternatif: vcpkg (`vcpkg install capstone unicorn keystone`) veya sistem
kurulumu — CMake `find_package/find_path/find_library` ile otomatik bulur.

## Sürüm notları
- Capstone 6.0.0 şu an alpha serisinde (Alpha11, Eylül 2026); bu depo
  kararlı 5.0.7 ile gelir. 6.x çıktığında API büyük ölçüde uyumludur.
- Unicorn 2.1.x gereklidir (1.x API'si farklıdır).
