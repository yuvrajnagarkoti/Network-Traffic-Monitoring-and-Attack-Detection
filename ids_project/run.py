"""
Application entry point.

Run with:
    flask run                    (development)
    gunicorn -k eventlet run:app (production)
"""

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
