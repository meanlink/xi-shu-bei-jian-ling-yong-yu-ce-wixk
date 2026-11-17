import os
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./local.db')
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
JWT_SECRET = os.environ.get('JWT_SECRET', 'local-development-change-before-deploy')
ARTIFACT_DIR = os.getenv('ARTIFACT_DIR', '/artifacts')
# 归档加密密钥与归档文件分开保存，不能位于同一目录树。
ARCHIVE_KEY_DIR = os.getenv('ARCHIVE_KEY_DIR', '/archive-keys')
