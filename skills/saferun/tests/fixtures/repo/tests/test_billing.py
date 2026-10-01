from billing import charge, refund


def test_charge():
    result = charge(10)
    assert result["status"] == "charged"
    assert result["currency"] == "USD"


def test_refund():
    result = refund("ch_1")
    assert result["status"] == "refunded"
    assert result["charge_id"] == "ch_1"
