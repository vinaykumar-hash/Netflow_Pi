from django.urls import path
from .views import (
    AutoencoderDetectionDisableView,
    AutoencoderDetectionEnableView,
    AutoencoderStatusView,
    AutoencoderTrainStartView,
    AutoencoderTrainStopView,
    ChatProxyView,
    NetworkDevicesView,
    NetworkInterfacesView,
    PacketUpdateView,
    SpoofStartView,
    SpoofStopView,
    WhitelistSettingsView,
)

urlpatterns = [
    path('update/', PacketUpdateView.as_view(), name='packet-update'),
    path('chat/', ChatProxyView.as_view(), name='chat-proxy'),
    path('network/devices/', NetworkDevicesView.as_view(), name='network-devices'),
    path('network/interfaces/', NetworkInterfacesView.as_view(), name='network-interfaces'),
    path('network/spoof/start/', SpoofStartView.as_view(), name='spoof-start'),
    path('network/spoof/stop/', SpoofStopView.as_view(), name='spoof-stop'),
    path('settings/whitelist/', WhitelistSettingsView.as_view(), name='settings-whitelist'),
    path('autoencoder/status/', AutoencoderStatusView.as_view(), name='autoencoder-status'),
    path('autoencoder/train/start/', AutoencoderTrainStartView.as_view(), name='autoencoder-train-start'),
    path('autoencoder/train/stop/', AutoencoderTrainStopView.as_view(), name='autoencoder-train-stop'),
    path('autoencoder/detection/enable/', AutoencoderDetectionEnableView.as_view(), name='autoencoder-detect-enable'),
    path('autoencoder/detection/disable/', AutoencoderDetectionDisableView.as_view(), name='autoencoder-detect-disable'),
]
