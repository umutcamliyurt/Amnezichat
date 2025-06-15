<div align="right">
  <a href="README.md">🇺🇸 English</a> |
  <a href="README_TR.md">🇹🇷 Türkçe</a>
</div>

# Amnezichat

<img src="banner.png" width="1200">

## İz bırakmayan güvenli mesajlaşma
<!-- AÇIKLAMA -->
## Açıklama:

Bir anti-forensik mesajlaşma uygulaması, dijital iletişimlerin gizliliğini ve güvenliğini artırarak önemli avantajlar sunar. Bu uygulama, adli araştırmacıların veya kötü niyetli aktörlerin mesajları ve ilgili meta verileri geri kazanmasını, analiz etmesini veya izini sürmesini engellemek için tasarlanmıştır. Gelişmiş şifreleme, güvenli silme yöntemleri ve belirsizlik teknikleri kullanarak, bu mesajlaşma uygulamaları silinmiş veya gizlenmiş iletişimlerin neredeyse geri kazanılamaz olmasını sağlar.

<!-- ÖZELLİKLER -->
## Özellikler:

- Kuantum dirençli uçtan uca mesaj şifreleme

- Bire bir sohbetler için forward ve backward secrecy

- PSK (önceden paylaşılan anahtar) kullanarak grup sohbeti desteği

- En ucuz donanımda bile çalışabilen sunucu

- Her mesaj sunucunun RAM'inde şifreli olarak saklanır ve 10 dakika sonra silinir

- Tor/I2P desteği

- Docker desteği

- Rust ile geliştirilmiştir

## Diğer mesajlaşma uygulamalarıyla karşılaştırma tablosu:

| Özellik                  | **Amnezichat**         | **Signal**            | **Simplex**           | **WhatsApp**                    | **Telegram**           | **Cwtch**             |
|--------------------------|---------------------------|---------------------------|---------------------------|-------------------------------------|---------------------------|------------------------------|
| **Geçici Mesajlar**      | Tamamen geçici            | İsteğe bağlı              | Tamamen geçici            | İsteğe bağlı                        | İsteğe bağlı              | Tamamen geçici               |
| **Şifreleme**            | Kuantum dirençli      | Kuantum dirençli      | Kuantum dirençli      | Signal Protokolü *(kapalı kaynak)* | Kısmi                     | Tor tabanlı              |
| **Forward Secrecy**     | ✅ Evet                   | ✅ Evet                   | ✅ Evet                   | ✅ Evet                             | ⚠️ Kısmi                 | ✅ Evet                       |
| **Trafik Yönlendirme**   | 🔄 İsteğe bağlı (Tor/I2P) | ❌ Hayır                  | 🔄 İsteğe bağlı           | ❌ Hayır                            | ❌ Hayır                  | ✅ Tor üzerinden              |
| **Veri Saklama**         | 🗑️ Yok                    | 🗑️ Yok                   | 🗑️ Yok                   | ❌ Meta veri silinmez            | ❌ Meta veri silinmez | 🗑️ Yok                        |
| **Grup Sohbeti**         | 🔐 Evet (PSK tabanlı)     | ✅ Evet                   | ✅ Evet                   | ✅ Evet                             | ✅ Evet                   | ✅ Evet                       |
| **FOSS (Açık Kaynak)**   | ✅ Evet                   | ✅ Evet                   | ✅ Evet                   | ❌ Hayır                            | ❌ Hayır                  | ✅ Evet                       |
| **Kendin Barındırabilir**| ✅ Evet                   | ❌ Hayır                  | ✅ Evet                   | ❌ Hayır                            | ❌ Hayır                  | ✅ Evet                       |
| **Sunucu Gereksinimi**   | ✅ Düşük maliyetli donanım| ❌ Orta düzey             | ❌ Orta düzey             | ❌ Yüksek                           | ❌ Orta/Yüksek           | ✅ Sadece P2P         |



## Teknik detaylar:

- Şifreli sahte veriler göndererek ve tüm mesajları sabit bir uzunluğa sabitleyerek AI destekli trafik analizine (DAITA) karşı savunma

![paket_yakalama](packet_capture.png)

- Uçtan uca şifreleme için [Amnezichat Protokolü](PROTOCOL_TR.md)
- Kimlik anahtarlarını, kullanıcı tarafından belirlenen bir şifre ile ChaCha20-Poly1305 ve Argon2id KDF kullanarak yerel depolamada şifreler

### Amnezichat Protokolü:
- Kimlik doğrulama için EdDSA ve Dilithium5, anahtar değişimi için ECDH ve Kyber1024, şifreleme için ChaCha20-Poly1305

<!-- KURULUM -->
## İstemci kurulumu:

    sudo apt update
    sudo apt install curl build-essential git tor xterm
    sudo systemctl enable --now tor.service
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    git clone https://git.disroot.org/Amnezichat/Amnezichat.git
    cd Amnezichat/client/
    cargo build --release
    cargo run --release

## Docker ile istemci kurulumu:

    sudo apt update
    sudo apt install docker.io git
    git clone https://git.disroot.org/Amnezichat/Amnezichat.git
    cd Amnezichat/client/
    docker build --network=host -t amnezichat .
    xhost +local:docker
    docker run --rm \
    --network=host \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    --env QT_X11_NO_MITSHM=1 \
    amnezichat:latest

## Gereksinimler:

- [Rust](https://www.rust-lang.org), [Tor](https://gitlab.torproject.org/tpo/core/tor), [I2P](https://i2pd.website/)

<!-- EKRAN GÖRÜNTÜSÜ -->
## Ekran görüntüsü:

![Ekran görüntüsü](screenshot.png)

<!-- AYNALAR -->
## Git Aynaları

**Amnezichat** kaynak koduna birden fazla yedek (ayna) depo üzerinden erişebilirsiniz:

- 🔗 **[Ana Depo (Disroot)](https://git.disroot.org/Amnezichat/Amnezichat)**
- 🔗 **[GitHub Aynası](https://github.com/Amnezichat/Amnezichat)**

<!-- LİSANS -->
## Lisans

GPLv3 Lisansı altında dağıtılmaktadır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

## <a href="CONTRIBUTORS_TR.md">Destekçiler</a>

## Bu projenin geliştirilmesini desteklemek için bağış yapın!

**Monero(XMR):** 88a68f2oEPdiHiPTmCc3ap5CmXsPc33kXJoWVCZMPTgWFoAhhuicJLufdF1zcbaXhrL3sXaXcyjaTaTtcG1CskB4Jc9yyLV

**Bitcoin(BTC):** bc1qn42pv68l6erl7vsh3ay00z8j0qvg3jrg2fnqv9
