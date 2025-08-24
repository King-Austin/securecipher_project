# middleware/tests/test_views.py
import pytest
from django.urls import reverse

@pytest.mark.django_db
def test_get_public_key(client):
    url = reverse("get_public_key")
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert "public_key" in data
    assert isinstance(data["public_key"], str)
