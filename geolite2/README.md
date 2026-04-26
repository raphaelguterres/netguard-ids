# GeoLite2 — bases de geolocalização (opcional)

NetGuard usa MaxMind GeoLite2 quando os arquivos `.mmdb` estiverem aqui.
Sem eles, cai pro prefix DB embutido (`geo_ip.GEO_DB`) — funciona, mas
cobre só os ranges curados.

## Obter os DBs

1. Crie uma conta gratuita em https://www.maxmind.com (precisa só de e-mail).
2. Em "My Account" → "Manage License Keys", gere uma chave.
3. Baixe **GeoLite2-City.mmdb** e (opcionalmente) **GeoLite2-ASN.mmdb**
   da página de Downloads.
4. Substitua os arquivos placeholder neste diretório pelos `.mmdb` reais:
   - `geolite2/GeoLite2-City.mmdb` (~70 MB) — país/cidade/lat/lon
   - `geolite2/GeoLite2-ASN.mmdb`  (~7 MB)  — autonomous system / org

Caminho customizado: defina `IDS_GEOLITE2_DB` e/ou `IDS_GEOLITE2_ASN_DB`
apontando pra qualquer outro path absoluto.

## Verificação

```python
import geo_ip
print(geo_ip.geolite2_status())
# {'city_loaded': True, 'asn_loaded': True, ...} se carregou
```

Endpoint: `GET /api/admin/geolite2/status` (admin-only).

## Atualização

GeoLite2 é atualizado pela MaxMind ~3x por semana. Para reload, basta
reiniciar o app — o reader carrega no primeiro `lookup()` que precisar.

## Licença

Este projeto **não inclui** os arquivos `.mmdb` — eles são distribuídos
pela MaxMind sob a [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula).
Cada usuário precisa baixá-los com sua própria license key.
