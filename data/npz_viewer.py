import numpy as np

# 假设文件在桌面
file_path = r'C:\Users\Admin\Desktop\IoHT-Project\1\Improved\Security\data\ECU_ready_scientific_no_smote.npz'

# 或者使用相对路径（如果脚本和数据文件在同一目录）
# file_path = 'ECU_ready_scientific_no_smote.npz'

try:
    data = np.load(file_path)
    print("Keys:", data.files)
    for key in data.files:
        print(f"{key}: {data[key].shape} {data[key].dtype}")
except FileNotFoundError:
    print(f"文件未找到: {file_path}")
    print("请检查文件路径是否正确。")