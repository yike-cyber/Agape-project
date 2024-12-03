
from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from .views import home

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',home,name = 'home'),
    path('api/',include('api.urls')),
    
]

urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#custom error responses
# handler404 = 'agape.views.custom_page_not_found'
# # handler500 = 'agape.views.custom_server_error'
# handler400 = 'agape.views.custom_bad_request'
# handler401 = 'agape.views.custom_unauthorized'
# handler403 = 'agape.views.custom_forbidden'
# handler422 = 'agape.views.custom_unprocessable_entity'
