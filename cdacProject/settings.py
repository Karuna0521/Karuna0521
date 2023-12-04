"""
Django settings for cdacProject project.

Generated by 'django-admin startproject' using Django 4.1.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from datetime import timedelta
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-cl24gr1h^(qud$2@_atpz0&(&i!ty!bx%y*7b$kwc9a%tlx2r$'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# settings.py
APPEND_SLASH = False


# Application definition
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_ALLOW_ALL = True
# CORS_ALLOWED_ORIGINS = [
#     "http://10.244.0.161:8000",
#     "http://10.244.1.208:3001",
# ]
CORS_ALLOW_METHODS = (
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
)
CORS_ALLOW_HEADERS = [
    'Content-Type', 'Authorization'
    # Add any other allowed headers here.
]
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'checklistApp.apps.ChecklistappConfig',
    'rest_framework',
    'rest_framework.authtoken', 
    'django.contrib.auth.password_validation',
    'rest_framework_simplejwt',
    'corsheaders',
    
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cdacProject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'cdacProject.wsgi.application'
# CORS_ALLOWED_ORIGINS = ["*"]
ALLOWED_IPS = ['*']


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'CDACchecklist',
        'HOST': '127.0.0.1',
        'PORT': 27017,
    }
}
# Rest Framework Requirements

AUTH_USER_MODEL = 'checklistApp.User'
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',),
}
REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # 'rest_framework.authentication.TokenAuthentication',
        # 'rest_framework.authentication.BasicAuthentication',
        # 'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

SIGNING_KEY = '''-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCphe7GXcY4ULhW
70y1F6zOfW+qXggtukTkWlrJ06br517U6R9Jv6zlvU1vATYwF04ZKv+mvRhKP5By
gBEoQIsJIEXV6nzigoi7tegZjLRaFPyNgwQ5aRd4majo0dEgHur7DsUkjkNGQGca
DQgxl0qg7EY43X89ddqNCDE65ic7YbQ8FLAVjjSKoH5Mgwba6I8PrmxkHSoAxX1P
0LS/bUi4ivIdCiuJqye09tktT+puFEINc1SM7kWHCFAk7yewzqPU2oI7c7IX4o3J
IdEt7UC9N4RlzhU/QUTYRmRXISzZiSKghXaXJ7tMX49ApnfqTbTf2XFIN+ED3F+I
cP1G8gedAgMBAAECggEAIU8EnIteYEBUCBja3JY7SRNSdoolVz7LPIcYYaGpoZ6D
fpgTorz7ruRkK5R0XjymBsHxG4T6GdSlgCnztRIBf5iMwDxjr2nwjdlvMl34Ld8D
xJZipRkmGHcwvhZD3ejVSOEdEVK2mz4aQ/8dhgjxC++A2LmEv8HBYIakjasdOEhm
v8pqDRQhKBn7YU3YyerWFu33ol7PfcSi5SuGHAAihc63lqF5Dw1J+gYAexImvQ4f
MaHmAkoCDCsSKQhQ7CA8yH5wRezipsvu1UnCRqZHhQ0EhLR2KBoCNkpGIJE3TMR+
LWIiyJAgAh6F9XVEBhURsNu7aR+twVRyiagvwn2ijQKBgQC27nBWY7ymkQfgm0Eg
cGc4G6oGHv8us7KO67wbBQxj4AhJdZZb8LwwQWMm7fzWKbxjLWJli6arqHKHjIoF
KW1Hsive96TCjwgQG1tLxeb/ATP6OSDKepgQkjrPDCcauGJSAl4WwI6nFg7QpIIi
3JY/D/62zN4a7477JazSVyUlwwKBgQDtPHEzg7FDnh+nbZmSILd0OMhKMTAns9A4
IZeRK0ZDf1yjvJqakN/+//PyesEe+nhuBOIAy1LtGvCNDSnAxKDwctr+3datdVvr
dDrUhbHhhs2c3hwl4Py8RQB2M/z+8frC0sBKiE+MwxkO2P3LX/XFGLAUYkea/5Ai
H1FKWqtnHwKBgQCSES4uLRFzxxaNKCsGpfoleSF4JcQJHH+VU3It+Qf9r+OuFHBt
FXqO5YcwjJN4xnagkpqhDrOVGbnptjR3Dq8tsn0JWqB6og8EHXP2ux1JvUItqPQf
+Wf2w2yl6sRGt7f6V92dOUAu9pP50YIAKDboP/NZL5ih1WtL6rdmdSM6VQKBgQCG
VIQwzC/yfrWjwz6C7L2UNJbM099Vi86qCfNdwugtTg+xsxjDzqbXKC0ErxdtKBxL
B77E/lw9X9S3ua1btrr+i7qPOCPX4i0jPJQXRIC9l+wTF/1OQYA6RsQFKljmLzRz
Xox9Z4PLy6kDrEDBCNwMN3d0g1XSYUVG3P7VoFOPtwKBgQCGikESYVzDY5tdRWW3
gGp0YT8neIkaREtayYxxXiHPnifQ62gGaCIGud5Ryeo8xCdmMphllXnUm91M4ctG
8wSItxc2T6ScPCV30GGy0a7y+bdZviL3ka/ut5kqlEaAqg04tEO2bPk2x1JoU4St
ms1f3D3FszmvXepZVlXj/6xjyg==
-----END PRIVATE KEY-----'''

VERIFYING_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYXuxl3GOFC4Vu9MtRes
zn1vql4ILbpE5FpaydOm6+de1OkfSb+s5b1NbwE2MBdOGSr/pr0YSj+QcoARKECL
CSBF1ep84oKIu7XoGYy0WhT8jYMEOWkXeJmo6NHRIB7q+w7FJI5DRkBnGg0IMZdK
oOxGON1/PXXajQgxOuYnO2G0PBSwFY40iqB+TIMG2uiPD65sZB0qAMV9T9C0v21I
uIryHQoriasntPbZLU/qbhRCDXNUjO5FhwhQJO8nsM6j1NqCO3OyF+KNySHRLe1A
vTeEZc4VP0FE2EZkVyEs2YkioIV2lye7TF+PQKZ36k2039lxSDfhA9xfiHD9RvIH
nQIDAQAB
-----END PUBLIC KEY-----'''


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": False,

    "ALGORITHM": "RS256",
    "SIGNING_KEY": SIGNING_KEY,
    "VERIFYING_KEY": VERIFYING_KEY,
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,

    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=60),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}


JWT_ALGORITHM = "RS256"
JWT_PRIVATE_KEY_PATH = SIGNING_KEY
JWT_PUBLIC_KEY_PATH = VERIFYING_KEY
JWT_ISSUER = "checklistApp"
JWT_AUDIENCE = "login"
JWT_EXPIRATION_DELTA = timedelta(days=1)


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
