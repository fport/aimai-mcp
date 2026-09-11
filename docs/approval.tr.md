# İnsan onayı

Neyin insan gerektirdiğine karar vermek için cazip eksen "bu ne kadar
tehlikeli hissettiriyor" — kimsenin kazanamadığı bir tartışma üretir. İşe
yarayan eksen, evet/hayır cevabı olan bir soru:

**Dünyayı geri koyan bir çağrı var mı?**

| Sınıf | Örnek | Geri alma | Kapı |
|---|---|---|---|
| Okuma | `run_query` | bir şey olmadı | otomatik |
| Geri alınabilir yazma | `update_ticket_status` | önceki status'e dön | otomatik + audit |
| Geri alınamaz | `refund_invoice`, `send_customer_email` | yok | tek imza |
| Yetki genişletme | `grant_agent_access` | geri alınabilir ama siz fark etmeden kimin davranabileceğini genişletir | iki imza |

Yanlışlıkla kapanmış bir ticket'ı gözünde canlandıran birine
`update_ticket_status`, `send_customer_email`'den daha tehlikeli *hissettirir*.
Değil. Status tek çağrıyla geri döner; gönderilmiş bir mesaj hiç dönmez.

Bu, sınıflandırmanın ima ettiğinden daha önemli. Tek çağrıyla geri alınan bir
şey için insanı durdurmak, ona onay tuşuna bakmadan basmayı öğretmenin
yoludur — ve okumadan bastığı onay, iade onayıdır.

Server burada işi bir tabloya bırakmak yerine yardım ediyor: her yazma kendi
undo'sunu döndürüyor.

```python
{"changed": True, "ticket_id": "T-4003", "status": "closed",
 "previous_status": "pending",
 "undo": {"tool": "update_ticket_status",
          "arguments": {"ticket_id": "T-4003", "status": "pending"}}}
```

```python
{"changed": True, "invoice_id": "INV-7002", "status": "refunded",
 "amount": 39900,
 "undo": None}          # para çıktı; buradaki hiçbir şey onu geri getirmiyor
```

## İkinci imza

Bu depoda agent yerine *onaylayan kişi* hakkında olan tek kural. "Bu adrese
admin ver" onayını veren kişi, çoğu zaman bundan fayda sağlayan kişidir; bu
yüzden `grant_agent_access` farklı kişilerden iki imza istiyor ve kapı aynı
adı iki kez reddediyor:

```text
outcome.reason == "nadia already signed this request"
```

Ayrıca onaylayanın da geçemeyeceği bir policy kısıtı var: bir agent erişimi
genişletebilir, ama asla erişimi tekrar genişletebilecek role kadar değil.

```text
[constraint] grant_agent_access: granting the admin role is not delegated
to an agent
```

## Kapıyı ölçmek

Kapı her talebi ve her kararı zaman damgalıyor, çünkü kapının çalışıp
çalışmadığını iki sayı söylüyor:

- **onay / ret oranı** — her şeyi onaylayan bir kapı bir log satırıdır
- **kuyruk p50 / p95** — p95'i iki gün olan bir kapı hiçbir şeyi korumaz,
  etrafından dolaşılır

İkisi de [Sonuçlar](results.tr.md) sayfasında, ve gecikme satırı henüz neyi
ölçmediği konusunda dürüst.
