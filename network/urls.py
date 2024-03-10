"""network URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app_info import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index),
    path('scan_network/', views.scan_network),
    path('escanear_red/', views.escanear_red_view),

    path('info_ip/<str:ip>/', views.info_ip),
    path('info_equipo/<str:ip>/', views.info_equipo),

    path('estado_ips/', views.estado_ips, name='estado_ips'),
    path('ip_active/', views.ip_active, name='ip_active'),

    path('view_device/', views.mostrar_dispositivos, name='mostrar_dispositivos'),

    path('mostrar_informacion_hardware/', views.mostrar_informacion_hardware, name='mostrar_informacion_hardware'),
]
