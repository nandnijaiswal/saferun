"""Tiny fixture module used by SafeRun's golden tests."""


def charge(amount, currency="USD"):
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"amount": amount, "currency": currency, "status": "charged"}


def refund(charge_id, amount=None):
    return {"charge_id": charge_id, "amount": amount, "status": "refunded"}


def format_receipt(payment):
    return f"{payment['amount']} {payment['currency']}"
