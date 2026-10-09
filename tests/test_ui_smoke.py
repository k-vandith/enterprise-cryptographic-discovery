def test_ui_entrypoint():
    import src.app as app
    assert callable(app.main)
