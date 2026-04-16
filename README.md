# 压缩包密码破解工具

## 项目介绍

这是一款功能强大的压缩包密码破解工具，支持多种压缩格式和攻击模式，界面友好，操作简单。

## 功能特点

### 支持的压缩格式
- **ZIP** - 支持传统加密和AES加密
- **RAR** - 需要系统安装unrar工具
- **7z** - 支持7z格式的密码破解

### 攻击模式
1. **字典攻击** - 从文本文件读取密码进行尝试
2. **暴力枚举** - 根据指定的字符集和长度范围生成密码
3. **掩码攻击** - 使用占位符生成有特定规律的密码
4. **自定义生成器** - 编写Python代码动态生成密码

## 使用方法

1. **选择目标文件**：点击"浏览"按钮选择要破解的压缩包
2. **选择攻击模式**：
   - **字典攻击**：选择包含密码的文本文件
   - **暴力枚举**：设置字符集和长度范围
   - **掩码攻击**：使用占位符设置密码模式（如 `?l?l?l?d?d?d`）
   - **自定义生成器**：编写Python代码生成密码
3. **性能设置**（可选）：启用性能模式并设置刷新间隔
4. **开始破解**：点击"开始破解"按钮
5. **查看结果**：破解过程中会显示实时进度，找到密码后会在日志中显示

## 掩码占位符说明
- `?l` - 小写字母 (a-z)
- `?u` - 大写字母 (A-Z)
- `?d` - 数字 (0-9)
- `?s` - 特殊字符 (!@#$%^&*()_+-=[]{}|;:,.<>?/~)
- `?a` - 所有字符

## 自定义生成器示例

```python
# 自定义密码生成器模板
def generator():
    from datetime import date, timedelta
    letters = [('A', 'a'), ('B', 'b'), ('C', 'c')]
    import itertools
    prefixes = [''.join(p) for p in itertools.product(*letters)]
    start = date(2024, 1, 1)
    end = date(2025, 12, 31)
    delta = timedelta(days=1)
    current = start
    while current <= end:
        date_str1 = current.strftime('%Y%m%d')
        date_str2 = f"{current.year}{current.month}{current.day}"
        for prefix in prefixes:
            yield prefix + date_str1
            yield prefix + date_str2
        current += delta

def total():
    from datetime import date
    days = (date(2025, 12, 31) - date(2024, 1, 1)).days + 1
    return days * 8 * 2
```

## 注意事项

1. **RAR破解**：需要 `UnRAR.exe` 工具，已包含在压缩包中
2. **性能考虑**：暴力破解和掩码破解的密码长度过长会导致组合数爆炸式增长，可能需要极长的时间
3. **合法性**：本工具仅供合法授权的安全测试、数据恢复及教育用途，请勿用于非法用途

### Q: RAR文件破解失败怎么办？
A: 确保 `UnRAR.exe` 在同一目录，或已添加到系统PATH

### Q: 破解速度很慢怎么办？
A: 启用性能模式，或尝试使用字典攻击

### Q: 中文密码支持吗？
A: 支持，工具会自动尝试UTF-8、GBK、Latin-1编码

## 免责声明

本工具仅供合法授权的安全测试、数据恢复及教育用途。使用本工具进行任何未经授权的破解行为均可能违反法律法规，使用者需自行承担相应责任。

---

**开源协议：MIT**