from rest_framework.views import APIView
from django.db.models import Sum
from rest_framework.response import Response
from rest_framework import status, permissions, serializers
from django.db import transaction
from django.shortcuts import render
from .models import User, Transaction
from .serializers import (
    UserRegistrationSerializer, UserSerializer,
    TransactionSerializer, TransferSerializer
)
from .crypto_utils import CryptoUtils
import json




def index_view(request):
    """Render the SecureCipher Banking API landing page"""
    return render(request, 'index.html')


def authenticate_user_by_public_key(transaction_data):
    """
    Authenticate user by checking if the public_key in transaction_data 
    exists in the User table.
    Returns (user, error_message)
    """
    public_key = transaction_data.get('public_key')
    if not public_key:
        return None, "Authentication failed: public_key is required"
    
    try:
        user = User.objects.get(public_key=public_key)
        return user, None
    except User.DoesNotExist:
        return None, "Authentication failed: Invalid public key"
    except Exception as e:
        return None, f"Authentication failed: {str(e)}"


class PublicKeyView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        print("DEBUG: [PublicKeyView.get] Called")
        public_key = CryptoUtils.get_server_public_key()
        print(f"DEBUG: [PublicKeyView.get] public_key={public_key}")
        if not public_key:
            print("DEBUG: [PublicKeyView.get] Public key not found")
            return Response({'error': 'Public key not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'public_key': public_key}, status=status.HTTP_200_OK)


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print("DEBUG: [RegisterView.post] Received request data:", request.data)


        transaction_data, session_key, client_info_or_error = CryptoUtils.crypto_preprocess(request.data)

        
        print(f"DEBUG: [RegisterView.post] transaction_data={transaction_data}, session_key={session_key}, client_info_or_error={client_info_or_error}")

        if isinstance(client_info_or_error, str):  # Error string
            print(f"DEBUG: [RegisterView.post] Crypto error: {client_info_or_error}")
            return encrypted_response(session_key, {"error": client_info_or_error}, status.HTTP_400_BAD_REQUEST)

        transaction_data['account_number'] = transaction_data.get("phone_number").lstrip('0').replace('+234', '').replace(' ', '').replace('-', '')[:10]
        print("DEBUG: [RegisterView.post] transaction_data after account_number processing:", transaction_data)
        serializer = UserRegistrationSerializer(data=transaction_data)
        print("DEBUG: [RegisterView.post] serializer.is_valid() check")
        if not serializer.is_valid():
            print("DEBUG: [RegisterView.post] serializer.errors:", serializer.errors)
            return encrypted_response(session_key, serializer.errors, status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                print("DEBUG: [RegisterView.post] Saving user")
                user = serializer.save()
        except serializers.ValidationError as ve:
            print("DEBUG: [RegisterView.post] serializers.ValidationError:", ve.detail)
            return encrypted_response(session_key, ve.detail, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("DEBUG: [RegisterView.post] Exception:", str(e))
            return encrypted_response(session_key, {'error': str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)

        print("DEBUG: [RegisterView.post] User created:", user)
        
        # Prepare simple response for frontend
        user_data = UserSerializer(user).data
        
        transactions_data = TransactionSerializer(
            Transaction.objects.filter(account=user).order_by('-created_at'), many=True
        ).data
        
        response_payload = {
            'success': True,
            'message': f'Welcome to SecureCipher, {user.first_name}!',
            'user': user_data,
            'transactions': transactions_data
        }
        
        return encrypted_response(session_key, response_payload)


class TransferView(APIView):
    permission_classes = [permissions.AllowAny]

    def get_client_ip(self, request):
        """Extract client IP address from request headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request):
        print("DEBUG: [TransferView.post] Received request data:", request.data)
        transaction_data, session_key, error = CryptoUtils.crypto_preprocess(request.data)
        print(f"DEBUG: [TransferView.post] transaction_data={transaction_data}, session_key={session_key}, error={error}")

        if error:
            print("DEBUG: [TransferView.post] Crypto error:", error)
            return encrypted_response(session_key, {"error": error}, status.HTTP_400_BAD_REQUEST)

        # Authenticate user by public key
        authenticated_user, auth_error = authenticate_user_by_public_key(transaction_data)
        if auth_error:
            print(f"DEBUG: [TransferView.post] Authentication failed: {auth_error}")
            return encrypted_response(session_key, {"error": auth_error}, status.HTTP_401_UNAUTHORIZED)
        
        print(f"DEBUG: [TransferView.post] User authenticated: {authenticated_user.username}")

        serializer = TransferSerializer(data=transaction_data)
        print("DEBUG: [TransferView.post] serializer.is_valid() check")
        serializer.is_valid(raise_exception=True)

        sender = serializer.validated_data['source_account']
        recipient = serializer.validated_data['destination_account']
        amount = serializer.validated_data['amount']
        print(f"DEBUG: [TransferView.post] sender={sender}, recipient={recipient}, amount={amount}")

        # Verify authenticated user matches the source account
        if authenticated_user != sender:
            print("DEBUG: [TransferView.post] User mismatch: authenticated user does not match source account")
            return encrypted_response(session_key, {"error": "Authentication failed: You can only transfer from your own account"}, status.HTTP_403_FORBIDDEN)

        try:
            with transaction.atomic():
                print("DEBUG: [TransferView.post] Updating balances")
                

                sender.balance -= amount
                recipient.balance += amount
                sender.save()
                recipient.save()

                print("DEBUG: [TransferView.post] Creating Transaction records")
                

                
                # Create comprehensive transaction records with all fields
                debit_txn = Transaction.objects.create(
                    account=sender, 
                    amount=amount, 
                    transaction_type='DEBIT', 
                    status='COMPLETED',
                    balance_before=sender.balance + amount,
                    balance_after=sender.balance,
                    description=transaction_data.get('description', f"Transfer to {recipient.account_number}"),
                    recipient_account_number=recipient.account_number,
                    recipient_name=f"{recipient.first_name} {recipient.last_name}",
                    sender_name=f"{sender.first_name} {sender.last_name}",
                    sender_account_number=sender.account_number,
                )
                
                credit_txn = Transaction.objects.create(
                    account=recipient, 
                    amount=amount, 
                    transaction_type='CREDIT', 
                    status='COMPLETED',
                    balance_before=recipient.balance - amount,
                    balance_after=recipient.balance,
                    description=transaction_data.get('description', f"Transfer from {sender.account_number}"),
                    recipient_account_number=recipient.account_number,
                    recipient_name=f"{recipient.first_name} {recipient.last_name}",
                    sender_name=f"{sender.first_name} {sender.last_name}",
                    sender_account_number=sender.account_number,
                  
                )

            print("DEBUG: [TransferView.post] Transfer successful")
            
            # Return simple response
            response_data = {
                'success': True,
                'message': f'Successfully transferred ₦{amount} to {recipient.first_name} {recipient.last_name}',
                'balance': str(sender.balance),
                'user': UserSerializer(sender).data,
                'transactions': TransactionSerializer(
                    Transaction.objects.filter(account=sender).order_by('-created_at')[:10], 
                    many=True
                ).data
            }
            
            return encrypted_response(session_key, response_data)

        except Exception as e:
            print("DEBUG: [TransferView.post] Exception:", str(e))
            return encrypted_response(session_key, {'error': f'Transfer error: {str(e)}'}, status.HTTP_400_BAD_REQUEST)


class ValidateAccountView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print("DEBUG: [ValidateAccountView.post] Received request data:", request.data)
        transaction_data, session_key, error = CryptoUtils.crypto_preprocess(request.data)
        print(f"DEBUG: [ValidateAccountView.post] transaction_data={transaction_data}, session_key={session_key}, error={error}")

        if error:
            print("DEBUG: [ValidateAccountView.post] Crypto error:", error)
            return encrypted_response(session_key, {"error": error}, status.HTTP_400_BAD_REQUEST)

        # Authenticate user by public key
        authenticated_user, auth_error = authenticate_user_by_public_key(transaction_data)
        if auth_error:
            print(f"DEBUG: [ValidateAccountView.post] Authentication failed: {auth_error}")
            return encrypted_response(session_key, {"error": auth_error}, status.HTTP_401_UNAUTHORIZED)
        
        print(f"DEBUG: [ValidateAccountView.post] User authenticated: {authenticated_user.username}")

        account_number = transaction_data.get('account_number')
        print(f"DEBUG: [ValidateAccountView.post] account_number={account_number}")
        if not account_number:
            print("DEBUG: [ValidateAccountView.post] Account number missing")
            return encrypted_response(session_key, {'error': 'Account number is required.'}, status.HTTP_400_BAD_REQUEST)

        try:
            print("DEBUG: [ValidateAccountView.post] Querying User by account_number")
            user = User.objects.get(account_number=account_number)
            
            # Return only necessary user information to minimize data exposure
            user_data = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'username': user.username
            }
            
            print("DEBUG: [ValidateAccountView.post] Account found, limited user_data:", user_data)
            return encrypted_response(session_key, {'user': user_data})
        except User.DoesNotExist:
            print("DEBUG: [ValidateAccountView.post] Account not found")
            return encrypted_response(session_key, {'error': 'Account not found.'}, status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("DEBUG: [ValidateAccountView.post] Exception:", str(e))
            return encrypted_response(session_key, {'error': f'Validation failed: {str(e)}'}, status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    """Retrieve authenticated user's data and transactions"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        # Decrypt incoming payload
        transaction_data, session_key, error = CryptoUtils.crypto_preprocess(request.data)
        if error:
            return encrypted_response(session_key, {'error': error}, status.HTTP_400_BAD_REQUEST)

        # Authenticate by public key
        user, auth_error = authenticate_user_by_public_key(transaction_data)
        if auth_error:
            return encrypted_response(session_key, {'error': auth_error}, status.HTTP_401_UNAUTHORIZED)

        # Serialize user and transactions
        user_data = UserSerializer(user).data
        txns = TransactionSerializer(
            Transaction.objects.filter(account=user).order_by('-created_at'), many=True
        ).data

        return encrypted_response(session_key, {'user': user_data, 'transactions': txns})


# Utility function for encrypted + signed responses
def encrypted_response(session_key, payload, status_code=status.HTTP_200_OK):
    print(f"DEBUG: [encrypted_response] session_key={session_key}, payload={payload}")
    if not session_key:
        # Fallback: Return plain JSON if session_key is missing
        print("DEBUG: [encrypted_response] No session_key, returning plaintext payload")
        return Response(payload, status=status_code)

    try:
        # Convert Django ErrorDetail objects to standard format for consistent JSON serialization
        def normalize_payload(obj):
            if hasattr(obj, '__dict__') and hasattr(obj, 'string') and hasattr(obj, 'code'):
                # This is an ErrorDetail object, convert to string
                return str(obj)
            elif isinstance(obj, dict):
                return {k: normalize_payload(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [normalize_payload(item) for item in obj]
            else:
                return obj
        
        # Normalize the payload to ensure consistent serialization
        normalized_payload = normalize_payload(payload)
        print(f"DEBUG: [encrypted_response] normalized_payload={normalized_payload}")
        
        # Create canonical JSON for signing (this is what will be verified)
        payload_json = json.dumps(normalized_payload, separators=(',', ':'), sort_keys=True)
        print(f"DEBUG: [encrypted_response] payload_json for signing={payload_json}")
        
        signature = CryptoUtils.sign_message(CryptoUtils.get_server_private_key(), payload_json.encode())
        server_pubkey = CryptoUtils.get_server_public_key()
        
        structured_response = {
            'payload': normalized_payload,  # Use normalized payload for consistency
            'signature': signature,
            'server_pubkey': server_pubkey
        }
        
        print(f"DEBUG: [encrypted_response] structured_response: {structured_response}")
        
        # Encrypt the entire structured response
        encrypted = CryptoUtils.encrypt(json.dumps(structured_response).encode(), session_key)
        print(f"DEBUG: [encrypted_response] encrypted: {encrypted}")

        # Return simple {iv, ciphertext} format
        if isinstance(encrypted, dict):
            return Response({
                'iv': encrypted['iv'],
                'ciphertext': encrypted['ciphertext']
            }, status=status_code)
        
        return Response({'error': 'Encryption failed'}, status=500)
        
    except Exception as e:
        print(f"DEBUG: [encrypted_response] Failed: {e}")
        return Response({'error': 'Encryption or signing failed'}, status=500)



from django.utils.timezone import localtime

class AdminDashboardView(APIView):
    """Admin view to return all users, balances, and transaction insights"""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            # === 1. Global Stats ===
            total_users = User.objects.count()
            active_users = User.objects.filter(status="ACTIVE").count()
            total_balance = User.objects.aggregate(total=Sum("balance"))["total"] or 0
            total_transactions = Transaction.objects.count()
            total_credits = Transaction.objects.filter(transaction_type="CREDIT").count()
            total_debits = Transaction.objects.filter(transaction_type="DEBIT").count()
            completed_txns = Transaction.objects.filter(status="COMPLETED").count()
            failed_txns = Transaction.objects.filter(status="FAILED").count()

            # === 2. Per-user details ===
            profiles = []
            users = User.objects.exclude(username="admin")  # ✅ exclude admin
            for user in users:
                transactions = Transaction.objects.filter(account=user).order_by("-created_at")[:5]
                    # Trim public key PEM formatting
                clean_pubkey = None
                if user.public_key:
                    clean_pubkey = (
                        user.public_key
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replace("\n", "")
                        .strip()
                    )
                profiles.append({
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "full_name": f"{user.first_name} {user.last_name}".strip(),
                        "account_number": user.account_number,
                        "account_type": user.account_type,
                        "status": user.status,
                        "balance": float(user.balance),
                       "created_at": localtime(user.created_at).strftime("%Y-%m-%d %H:%M:%S"),  # ✅ localtime
                        "is_verified": user.is_verified,
                        "public_key": clean_pubkey,
                    },
                    "recent_transactions": TransactionSerializer(transactions, many=True).data
                })

            # === 3. Response ===
            return Response({
                "stats": {
                    "total_users": total_users,
                    "active_users": active_users,
                    "total_balance": total_balance,
                    "total_transactions": total_transactions,
                    "total_credits": total_credits,
                    "total_debits": total_debits,
                    "completed_transactions": completed_txns,
                    "failed_transactions": failed_txns,
                },
                "profiles": profiles
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)