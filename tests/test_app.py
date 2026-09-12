import sys
import os

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.app import app


def test_home():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_products():
    client = app.test_client()

    response = client.get("/products")

    assert response.status_code == 200


def test_product():
    client = app.test_client()

    response = client.get("/product/1")

    assert response.status_code == 200


def test_missing_product():
    client = app.test_client()

    response = client.get("/product/999")

    assert response.status_code == 404


def test_health():
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
