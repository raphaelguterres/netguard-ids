# NetGuard IDS — Docker Guide

## Requisitos

- Docker instalado ([docker.com](https://docs.docker.com/get-docker/))
- Linux ou Windows com WSL2 (para captura de pacotes)

---

## Início Rápido

### 1. Clona o repositório

```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
```

### 2. Build da imagem

```bash
docker build -t netguard-ids .
```

### 3. Roda o container

```bash
docker run -d \
  --name netguard \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v netguard_data:/data \
  -p 5000:5000 \
  netguard-ids
```

### 4. Abre o dashboard

👉 http://localhost:5000

---

## Explicação dos parâmetros

| Parâmetro | Por quê |
|-----------|---------|
| `--network host` | Acessa a interface de rede real do host (necessário para captura de pacotes) |
| `--cap-add NET_ADMIN` | Permissão para capturar pacotes com Scapy |
| `--cap-add NET_RAW` | Permissão para raw sockets |
| `-v netguard_data:/data` | Persiste o banco SQLite entre restarts |
| `-p 5000:5000` | Expõe o dashboard na porta 5000 |

---

## Comandos úteis

```bash
# Ver logs em tempo real
docker logs -f netguard

# Parar o container
docker stop netguard

# Reiniciar
docker start netguard

# Remover container (mantém dados no volume)
docker rm netguard

# Ver dados persistidos
docker volume inspect netguard_data

# Rodar os testes dentro do container
docker exec netguard pytest tests/ -v

# Entrar no container para debug
docker exec -it netguard bash
```

---

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `IDS_PORT` | `5000` | Porta do dashboard |
| `IDS_HOST` | `0.0.0.0` | Interface de bind |
| `IDS_DB_PATH` | `/data/netguard_soc.db` | Caminho do banco SQLite |
| `IDS_LOG_LEVEL` | `INFO` | Nível de log |
| `IDS_ABUSEIPDB_KEY` | `` | Chave da API AbuseIPDB (opcional) |

Exemplo com variáveis customizadas:

```bash
docker run -d \
  --name netguard \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v netguard_data:/data \
  -e IDS_ABUSEIPDB_KEY=sua_chave_aqui \
  -e IDS_LOG_LEVEL=WARNING \
  -p 5000:5000 \
  netguard-ids
```

---

## Sem captura de pacotes (modo limitado)

Se não precisar de captura de pacotes reais, roda sem as caps:

```bash
docker run -d \
  --name netguard \
  -v netguard_data:/data \
  -p 5000:5000 \
  netguard-ids
```

O SOC Engine, Correlation Engine e Risk Score continuam funcionando normalmente.
Apenas a captura de pacotes via Scapy fica desativada.

---

## Windows com Docker Desktop

1. Instala [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Habilita WSL2 nas configurações
3. Roda os mesmos comandos acima no PowerShell ou WSL2 terminal

> **Nota:** No Windows, `--network host` não funciona da mesma forma que no Linux.
> O dashboard ainda fica acessível em `http://localhost:5000`,
> mas a captura de pacotes pode capturar tráfego do container, não do host Windows.
> Para monitoramento completo no Windows, use a instalação nativa (sem Docker).

---

## Construindo para múltiplas arquiteturas

```bash
# Para distribuir para Linux x86 e ARM (Raspberry Pi, servidores cloud)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t raphaelguterres/netguard-ids:latest \
  --push .
```
