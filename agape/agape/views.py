from django.http import JsonResponse

def home(request):
    data = ['message', 'successfull api !']  # A list
    return JsonResponse(data, safe=False) 

# Custom 404 Not Found Response
def custom_page_not_found(request, exception):
    return JsonResponse({
        'status': 'error',
        'message': "The page you're looking for does not exist.",
        'error_code': 404
    }, status=404)

# # Custom 500 Internal Server Error Response
# def custom_server_error(request):
#     return JsonResponse({
#         'status': 'error',
#         'message': "An internal server error occurred. Please try again later.",
#         'error_code': 500
#     }, status=500)

# Custom 400 Bad Request Response (for invalid or missing data)
def custom_bad_request(request, exception):
    return JsonResponse({
        'status': 'error',
        'message': 'Bad request. Please check your input.',
        'error_code': 400
    }, status=400)

# Custom 401 Unauthorized Response (for missing or invalid authentication)
def custom_unauthorized(request, exception):
    return JsonResponse({
        'status': 'error',
        'message': 'You are not authorized to access this resource.',
        'error_code': 401
    }, status=401)

# Custom 403 Forbidden Response (for permissions issues)
def custom_forbidden(request, exception):
    return JsonResponse({
        'status': 'error',
        'message': 'You do not have permission to perform this action.',
        'error_code': 403
    }, status=403)

# Custom 422 Unprocessable Entity Response (for invalid or incorrect data)
def custom_unprocessable_entity(request, exception):
    return JsonResponse({
        'status': 'error',
        'message': 'Unprocessable entity. Check the data you provided.',
        'error_code': 422
    }, status=422)
    
