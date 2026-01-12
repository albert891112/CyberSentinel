from google.cloud import webrisk_v1
from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient
from rich import print


def _compute_diff():
    constraints = webrisk_v1.ComputeThreatListDiffRequest.Constraints(
        max_diff_entries=10000,  # 每次最多處理的條目數
        max_database_entries=500000,  # 本地資料庫最大條目數
        supported_compressions=[
            webrisk_v1.CompressionType.RICE,
        ]
    )
    
    request = webrisk_v1.ComputeThreatListDiffRequest(
        threat_type=webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
        version_token=b"",
        constraints=constraints,
    )
    
    client = WebRiskServiceClient()
    return client.compute_threat_list_diff(request=request)


import struct

class BitReader:
    """簡易的位元讀取器，用於處理 encoded_data"""
    def __init__(self, data: bytes):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0  # 0-7, current bit in byte
        self.data_len = len(data)

    def read_bits(self, num_bits):
        """讀取指定數量的 bits 並返回整數"""
        result = 0
        for _ in range(num_bits):
            if self.byte_idx >= self.data_len:
                raise EOFError("End of stream reached")
            
            # 讀取當前 byte 的特定 bit
            # 注意：Google 的實作通常是 Little Endian 或特定的 bit order，
            # 這裡假設標準 Big Endian bit order，如果解碼錯誤可能需要調整 bit 讀取順序
            # 根據 Google Safe Browsing/Web Risk 規範，通常是從 byte 的 MSB 讀到 LSB
            
            current_byte = self.data[self.byte_idx]
            bit = (current_byte >> (7 - self.bit_idx)) & 1
            
            result = (result << 1) | bit
            
            self.bit_idx += 1
            if self.bit_idx == 8:
                self.bit_idx = 0
                self.byte_idx += 1
        return result

    def read_unary(self):
        """讀取 Unary 編碼 (計算連續的 0，直到遇到 1)"""
        count = 0
        while True:
            bit = self.read_bits(1)
            if bit == 1:
                break
            count += 1
        return count

def decode_rice_golomb(encoded_data: bytes, first_value: int, rice_parameter: int, entry_count: int):
    """
    解碼 Rice-Golomb 數據
    :param encoded_data: API 回傳的 bytes (注意：不是打印出來的字串，而是原始 bytes)
    :param first_value: rice_hashes.first_value
    :param rice_parameter: rice_hashes.rice_parameter (k)
    :param entry_count: rice_hashes.entry_count
    """
    hashes = []
    
    # 1. 第一個值直接加入
    current_hash = first_value
    hashes.append(current_hash)
    
    reader = BitReader(encoded_data)
    
    # 2. 解碼剩餘的 entry_count - 1 個值
    # 注意：entry_count 包含了 first_value
    for _ in range(entry_count - 1):
        try:
            # Step A: 讀取 Quotient (Unary coding)
            q = reader.read_unary()
            
            # Step B: 讀取 Remainder (Binary coding, k bits)
            r = reader.read_bits(rice_parameter)
            
            # Step C: 計算 Delta
            # Delta = q * (2^k) + r
            delta = (q << rice_parameter) + r
            
            # Step D: 累加
            current_hash += delta
            hashes.append(current_hash)
            
        except EOFError:
            break
            
    return hashes



if __name__ == "__main__":
    response =_compute_diff()
    print(response)
    # ==========================================
    # 模擬您的數據輸入 (如何使用)
    # ==========================================

    # 1. 從您的 response 物件中獲取數據
    # 假設 response 是您的 protobuf 物件
    # raw_encoded_data = response.additions[0].rice_hashes.encoded_data 
    # first_val = response.additions[0].rice_hashes.first_value
    # param_k = response.additions[0].rice_hashes.rice_parameter
    # count = response.additions[0].rice_hashes.entry_count

    # 為了演示，這裡填入您提供的數值 (encoded_data 為示意，實際應用請用原始 bytes)
    input_first_value = response.additions.rice_hashes.first_value
    input_rice_parameter = response.additions.rice_hashes.rice_parameter
    input_entry_count = response.additions.rice_hashes.entry_count

    # 注意：您貼上的 encoded_data 是文字表示法 ("\244U...")
    # 在程式中，請確保您傳入的是 bytes 類型。
    # 這裡僅創建一個假的 bytes 作為範例
    dummy_encoded_bytes = response.additions.rice_hashes.encoded_data

    try:
        decoded_prefixes = decode_rice_golomb(
            dummy_encoded_bytes, 
            input_first_value, 
            input_rice_parameter, 
            input_entry_count
        )
        
        print(f"成功解碼! 總共取得 {len(decoded_prefixes)} 個 Hash 前綴")
        print(f"前 5 個 Hash: {decoded_prefixes[:5]}")
        
        # 接下來的動作：存入資料庫
        # save_to_database(decoded_prefixes)
        
    except Exception as e:
        print(f"解碼發生錯誤: {e}")
        print("可能是 encoded_data 轉換問題或 bit 讀取順序需微調")

