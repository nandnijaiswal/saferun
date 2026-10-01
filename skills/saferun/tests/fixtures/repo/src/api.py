from billing import charge, refund


def checkout(cart):
    return charge(sum(item["price"] for item in cart))


def cancel(order):
    return refund(order["charge_id"])
