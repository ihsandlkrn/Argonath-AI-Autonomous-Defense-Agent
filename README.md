
# Autonomous Defense Agent: Network Intrusion Detection System (NIDS)

This project presents an **Autonomous Network Intrusion Detection System (NIDS)** designed to detect cyber threats in real-time. By utilizing the **CIC-IDS2017** dataset, the system implements a robust data pipeline that addresses structural errors (packet duplication, mislabeling) and employs hybrid sampling techniques to overcome class imbalance.

## 🚀 Project Overview

Modern intrusion detection systems often suffer from overfitting due to flawed datasets. This project bridges the gap between state-of-the-art anomaly detection research and real-time network defense. The architecture integrates a bidirectional feature extraction module (mimicking real-time network flow behavior) with a hybrid machine learning model to categorize network traffic into **Benign** or specific **Attack Types**.

## 🛠️ Key Features

* 
**Data Cleaning Pipeline:** Resolves packet duplication and timestamp incoherence identified in the original CIC-IDS2017 dataset.


* **Hybrid Sampling:** Combines `SMOTE` (for minority class oversampling) and `RandomUnderSampler` (for benign class balancing) within a structured pipeline to prevent data leakage.
* 
**Feature Optimization:** Reduces 80+ network features to 6 highly predictive features (e.g., *Flow IAT Mean*, *Init_Win_bytes_forward*), ensuring low-latency performance in real-time environments.


* **Dual-Model Architecture:** Uses a binary classifier for fast "Attack/Benign" detection and a multi-class classifier for specific attack type identification.
* **Autonomous Reputation System:** Tracks IP reputation and autonomously quarantines malicious actors based on cumulative threat scores.

## 🏗️ Architecture

The system follows a three-layer architecture:

1. **Input Layer:** Captures live traffic or processes CSV logs.
2. **Processing Layer:** Performs feature extraction and runs inference through the binary and multi-class models.
3. **Decision Layer:** A hybrid engine that logs events and applies autonomous defense responses (e.g., IP reputation management).

## 📊 Performance Analysis

The model achieves an F1-score of over **99%** on test sets. Extensive evaluations were conducted on the impacts of data cleaning:

* **Feature Importance:** Key indicators like `Packet Length Variance` provide high-precision detection of volumetric attacks.
* **Confusion Matrix:** The multi-class model demonstrates excellent separation between attack types, including low-frequency classes like *Infiltration*.

## 📂 Repository Structure

* `/data_pipeline.py`: Production-ready pipeline for data cleaning, SMOTE, and scaling.
* `/train_model.py`: Training script with Stratified K-Fold cross-validation.
* `/agent_daemon.py`: The live sniffer that acts as an autonomous defense agent.

## 📝 Usage

1. **Data Preparation:** Place your raw data CSVs in RAW_DATA_DIR
2. **Run Pipeline:** ```bash
python data_pipeline.py
```

```


3. **Train Models:**
```bash
python train_model.py

```


4. **Deploy Agent:**
```bash
python agent_daemon.py

```

## ⚖️ Limitations & Future Work

* **Data Drift:** Real-world testing revealed performance gaps due to concept drift between the static CIC-IDS2017 environment and modern CDN-heavy traffic.
* **Future Work:** Implementation of time-window-based packet sequence analysis to bridge the gap between static training and live dynamic network streams.

---

*Developed by İhsan Dalkıran | Muğla Sıtkı Koçman University*

Elbette, hazırladığım `README.md` dosyasını profesyonel ve akademik bir dille Türkçeye çevirdim:

---

# Otonom Savunma Ajanı: Ağ Saldırı Tespit Sistemi (NIDS)

Bu proje, siber tehditleri gerçek zamanlı olarak tespit etmek için geliştirilmiş **Otonom bir Ağ Saldırı Tespit Sistemi (NIDS)** sunmaktadır. **CIC-IDS2017** veri setini temel alan sistem, veri setindeki yapısal hataları (paket çoğalması, yanlış etiketleme vb.) gidermek için güçlü bir veri hattı (data pipeline) uygular ve sınıf dengesizliği sorununu aşmak için hibrit örnekleme teknikleri kullanır.

## 🚀 Projeye Genel Bakış

Modern saldırı tespit sistemleri, genellikle hatalı veri setleri nedeniyle "aşırı öğrenme" (overfitting) sorunu yaşamaktadır. Bu proje, güncel anomali tespiti araştırmaları ile gerçek zamanlı ağ savunması arasındaki boşluğu kapatmayı hedeflemektedir. Sistem mimarisi, gerçek zamanlı ağ akış davranışını taklit eden çift yönlü (bidirectional) bir öznitelik çıkarım modülü ile ağ trafiğini **Normal** veya **Saldırı Türü** olarak sınıflandıran hibrit bir makine öğrenmesi modelini entegre eder.

## 🛠️ Temel Özellikler

* **Veri Temizleme Hattı:** Orijinal CIC-IDS2017 veri setinde tespit edilen paket çoğalması ve zaman damgası tutarsızlıklarını giderir.
* **Hibrit Örnekleme:** `SMOTE` (azınlık sınıfları için) ve `RandomUnderSampler` (normal sınıfı dengelemek için) yöntemlerini, veri sızıntısını (data leakage) engelleyen yapılandırılmış bir boru hattı içerisinde birleştirir.
* **Öznitelik Optimizasyonu:** 80'den fazla ağ özniteliğini, gerçek zamanlı ortamlarda düşük gecikme süresi sağlayan en öngörücü 6 özniteliğe (ör. *Flow IAT Mean*, *Init_Win_bytes_forward*) indirger.
* **Çift Model Mimarisi:** Hızlı "Saldırı/Normal" tespiti için ikili (binary) bir sınıflandırıcı ve saldırı türünü teşhis etmek için çok sınıflı (multi-class) bir sınıflandırıcı kullanır.
* **Otonom İtibar Sistemi:** IP adreslerinin itibar skorlarını takip eder ve kümülatif tehdit skorlarına dayanarak kötü niyetli aktörleri otonom olarak karantinaya alır.

## 🏗️ Mimari

Sistem üç katmanlı bir mimariyi takip eder:

1. **Girdi Katmanı:** Canlı ağ trafiğini yakalar veya CSV loglarını işler.
2. **İşleme Katmanı:** Öznitelik çıkarımını gerçekleştirir ve veriyi ikili ve çok sınıflı modeller üzerinden geçirir.
3. **Karar Katmanı:** Olayları loglayan ve otonom savunma yanıtlarını (ör. IP itibar yönetimi) uygulayan hibrit bir motor içerir.

## 📊 Performans Analizi

Model, test setlerinde **%99'un üzerinde F1-skoru** elde etmektedir. Veri temizleme süreçlerinin etkileri üzerine kapsamlı değerlendirmeler yapılmıştır:

* **Öznitelik Önemi:** `Packet Length Variance` gibi temel göstergeler, hacimsel saldırıların yüksek doğrulukla tespit edilmesini sağlar.
* **Karmaşıklık Matrisi (Confusion Matrix):** Çok sınıflı model, *Infiltration* gibi düşük frekanslı saldırı sınıfları dahil olmak üzere saldırı türleri arasında mükemmel bir ayrım göstermektedir.

## 📂 Depo Yapısı

* `/data_pipeline.py`: Veri temizleme, SMOTE ve ölçeklendirme için üretim aşamasına hazır hat.
* `/train_model.py`: Stratified K-Fold çapraz doğrulama ile model eğitim betiği.
* `/agent_daemon.py`: Otonom savunma ajanı olarak görev yapan canlı paket dinleyici.

## 📝 Kullanım

1. **Veri Hazırlığı:** Ham veri CSV dosyalarınızı `RAW_DATA_DIR` yoluna yerleştirin.
2. **Pipeline Çalıştır:** ```bash
python data_pipeline.py
```

```


3. **Modelleri Eğit:**
```bash
python train_model.py

```


4. **Ajanı Başlat:**
```bash
python agent_daemon.py

```



## ⚖️ Sınırlamalar ve Gelecek Çalışmalar

* **Veri Kayması (Data Drift):** Gerçek dünya testleri, statik CIC-IDS2017 ortamı ile modern CDN yoğunluklu trafik arasında kavram kayması nedeniyle performans farkları olduğunu göstermiştir.
* **Gelecek Çalışmalar:** Statik eğitim ile canlı ağ akışları arasındaki farkı kapatmak için zaman pencereli (time-window) paket dizisi analizinin uygulanması hedeflenmektedir.

---

*Geliştiren: İhsan Dalkıran | Muğla Sıtkı Koçman Üniversitesi*
