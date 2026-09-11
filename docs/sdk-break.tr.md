# SDK kırılması

Bu projeyi yazarken gerçekten vakit alan dört şey oldu. Hiçbiri protokol
spesifikasyonunda değil; dördü de Python SDK'sında.

## `FastMCP` kaldırıldı

```python
from mcp.server.fastmcp import FastMCP   # mcp 2.x'te ModuleNotFoundError
```

Yerine geleni:

```python
from mcp.server import MCPServer          # eski adı FastMCP
from mcp.server.mcpserver import Context  # eskiden mcp.server.fastmcp.Context
```

Dekoratörler — `@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()` — aynı kaldı;
kafa karıştıran da tam olarak bu. İnternetteki örneklerin çoğu hâlâ 1.x
import'uyla başlıyor ve gerisi birebir aynı görünüyor, yani kod import
patlayana kadar doğru duruyor. SDK'nın kendi hata mesajı migration guide'ı
adıyla söylüyor; kopyalamadan önce onu okuyun.

## Exception mesajları maskeleniyor, `ToolError` maskelenmiyor

```python
raise ValueError("limit must be at most 200")
# client'ın gördüğü: "Error executing tool run_query"

raise ToolError("limit must be at most 200; page with offset instead")
# client'ın gördüğü: "Error executing tool run_query: limit must be at most 200; …"
```

Varsayılan doğru. Başıboş bir `KeyError`, bağlantının diğer ucundaki kim
olursa olsun ona server'ın iç işleyişini anlatmamalı. Ama bu şu demek: modele
*ne yapması gerektiğini öğretmek* için yazılmış bir ret, bilerek `ToolError`
olarak fırlatılmalı. Aksi hâlde öğretici olması amaçlanan ret sessizce boş
bir duvara dönüşüyor.

## Hata fırlatan bir tool, başarılı bir çağrıdır

Sonuç normal bir `tools/call` sonucu olarak, `isError: true` taşıyarak
dönüyor. Yani yalnızca exception bekleyen bir middleware, başarısız bir
çağrıyı temiz bir çağrı olarak kaydeder ve dashboard'unuzdaki hata oranı
sonsuza kadar sıfır kalır. Buradaki audit middleware bunun yerine sonucu
inceliyor.

## DNS rebinding koruması container hostname'inizi reddediyor

İlk `docker compose up` şunu döndürdü:

```text
httpx.HTTPStatusError: Client error '421 Misdirected Request'
  for url 'http://reader:8811/mcp'
```

…ve bu, hostname'den hiç söz etmeyen bir anyio `ExceptionGroup`'unun içine
sarılmış hâlde geldi. SDK varsayılan olarak yalnızca `127.0.0.1` Host
header'ına izin veriyor.

Kolay çözüm korumayı kapatmak ve bu yanlış olan: o kontrol, operatörün
tarayıcısındaki bir sayfanın bir adı 127.0.0.1'e çözüp server'ı sürmesini
engelleyen şey. Bunun yerine izinli kümeyi yapılandırın:

```python
mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["reader:*", "127.0.0.1:*"],
        allowed_origins=[...],
    )
)
```

## `mcp<2` pin çakışması hakkında

Bir MCP kurulumunu iki Python ortamına bölmenin alışıldık gerekçesi şuydu:
agent SDK'ları `mcp<2` pinliyor, server ise 2.x istiyordu; hiçbir resolver
ikisini birden çözemiyordu.

**Bu çakışma artık yok.** `openai-agents` bugün `mcp<3,>=1.19.0` pinliyor,
`claude-agent-sdk` ise `mcp<3.0.0,>=1.23.0`; ikisi de `mcp 2.2.0` ile yan yana
temiz çözülüyor.

Ayrım yine de burada, pin'den daha uzun ömürlü üç gerekçeyle:

1. **Server'ın kimlik bilgileri agent'ın sürecinde yaşamamalı.** Reader bir
   veritabanı handle'ı tutuyor; agent bir model API anahtarı tutuyor ve gün
   boyu saldırganın kontrolündeki metni okuyor.
2. **Sürüm farkı normal hâl.** Agent runtime'ları SDK'nın aylarca gerisinden
   geliyor. Buradaki client bilerek `mcp<2` pinli ve bir 2.x server ile
   konuşuyor; bu çalışmayı bıraktığı gün bir test patlıyor. Wire protokolü
   sürümlü (burada `2025-11-25`), Python API'si değil.
3. **Read/write ayrımını gerçek kılan şey bu.** Reader, SQLite'ı
   `file:...?mode=ro` URI'siyle açıyor ve bunu engine'in kendisi zorluyor. Tek
   süreç olsaydı, hangi tool çağrılırsa çağrılsın yazılabilir handle bellekte
   duruyor olurdu.

Tek ortamda koşmak zorundaysanız server'ı da 1.x ile yazın ve bunu teknik borç
olarak kaydedin. Sonradan keşfedilmesine izin vermeyin.
