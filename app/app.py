from flask import Flask, render_template, jsonify

app = Flask(__name__)

products = [
    {
        "id": 1,
        "name": "Laptop Pro",
        "price": 850000,
        "category": "Informatique"
    },
    {
        "id": 2,
        "name": "Smartphone X",
        "price": 450000,
        "category": "Téléphonie"
    },
    {
        "id": 3,
        "name": "Casque Bluetooth",
        "price": 75000,
        "category": "Audio"
    }
]


@app.route("/")
def home():
    return render_template("index.html", products=products)


@app.route("/products")
def product_list():
    return jsonify(products)


@app.route("/product/<int:product_id>")
def product(product_id):
    product = next(
        (p for p in products if p["id"] == product_id),
        None
    )

    if product is None:
        return jsonify({"error": "Product not found"}), 404

    return jsonify(product)


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "ecommerce-api"
    })

