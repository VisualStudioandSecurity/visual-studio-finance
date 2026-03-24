import ccxt
import pandas as pd
import time

# Configuração da Exchange (Apenas leitura pública, sem necessidade de API Key para dados)
exchange = ccxt.binance()

SYMBOL = 'BTC/USDT'
TIMEFRAME = '4h'  # Foco no seu operacional de 4H

def fetch_data(symbol, timeframe):
    """Busca os candles mais recentes da Binance"""
    bars = exchange.fetch_ohlcv(symbol, timeframe=timeframe, limit=5)
    df = pd.DataFrame(bars, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
    return df

def is_shooting_star(open_p, high, low, close):
    """
    Lógica técnica do padrão Shooting Star:
    1. Sombra superior deve ser pelo menos 2x o tamanho do corpo.
    2. Corpo pequeno na parte inferior do candle.
    3. Sombra inferior muito pequena ou inexistente.
    """
    body = abs(close - open_p)
    upper_shadow = high - max(open_p, close)
    lower_shadow = min(open_p, close) - low
    
    # Critérios de validação do padrão
    is_upper_long = upper_shadow >= (2 * body)
    is_lower_short = lower_shadow <= (body * 0.5)
    
    return is_upper_long and is_lower_short

def start_scanner():
    print(f"--- Monitoramento Visual Studio Finance Iniciado ---")
    print(f"Ativo: {SYMBOL} | Timeframe: {TIMEFRAME} | Padrão: Shooting Star")
    
    while True:
        try:
            df = fetch_data(SYMBOL, TIMEFRAME)
            last_candle = df.iloc[-1] # Candle atual (ainda em formação)
            prev_candle = df.iloc[-2] # Último candle fechado
            
            # Verificamos o candle fechado para evitar sinais falsos
            if is_shooting_star(prev_candle['open'], prev_candle['high'], prev_candle['low'], prev_candle['close']):
                print(f"\n⚠️ ALERTA: Shooting Star Detectada em {prev_candle['timestamp']}")
                print(f"Preço de Fechamento: {prev_candle['close']}")
                print(f"Estratégia sugerida: Analisar MACD para possível entrada Short alavancada.")
            else:
                print(".", end="", flush=True)
                
            # Aguarda 60 segundos para a próxima verificação para evitar rate limit
            time.sleep(60)
            
        except Exception as e:
            print(f"\nErro na conexão: {e}")
            time.sleep(10)

if __name__ == "__main__":
    start_scanner()