from ipaddress import ip_address
import logging
from time import sleep
from flask import Flask

from flask import request, abort
import datetime
from datetime import timedelta
from pytimeparse.timeparse import timeparse
from threading import Thread
from werkzeug.serving import make_server

# This is the "database" of our dummy LAPI
class DataStore:
    def __init__(self) -> None:
        self.id = 0
        self.decisions = []
        self.bouncer_lastpull_by_api_key = {}

    def insert_decisions(self, decisions):
        for i, _ in enumerate(decisions):
            decisions[i]["created_at"] = datetime.datetime.now()
            decisions[i]["deleted_at"] = self.get_decision_expiry_time(decisions[i])
            decisions[i]["id"] = self.id
            self.id += 1
        self.decisions.extend(decisions)

    # This methods can be made more generic by taking lambda expr as input for filtering
    # decisions to delete
    def delete_decisions_by_ip(self, ip):
        for i, decision in enumerate(self.decisions):
            if ip_address(decision["value"]) == ip_address(ip):
                self.decisions[i]["deleted_at"] = datetime.datetime.now()

    def delete_decision_by_id(self, id):
        for i, decision in enumerate(self.decisions):
            if decision["id"] == id:
                self.decisions[i]["deleted_at"] = datetime.datetime.now()
                break

    def update_bouncer_pull(self, api_key):
        self.bouncer_lastpull_by_api_key[api_key] = datetime.datetime.now()

    def get_active_and_expired_decisions_since(self, since):
        expired_decisions = []
        active_decisions = []

        for decision in self.decisions:
            # decision["deleted_at"] > datetime.datetime.now()  means that decision hasn't yet expired
            if decision["deleted_at"] > since and decision["deleted_at"] < datetime.datetime.now():
                expired_decisions.append(decision)

            elif decision["created_at"] > since:
                active_decisions.append(decision)
        return active_decisions, expired_decisions

    def get_decisions_for_bouncer(self, api_key, startup=False):
        if startup or api_key not in self.bouncer_lastpull_by_api_key:
            since = datetime.datetime.min
            self.bouncer_lastpull_by_api_key[api_key] = since
        else:
            since = self.bouncer_lastpull_by_api_key[api_key]

        self.update_bouncer_pull(api_key)
        return self.get_active_and_expired_decisions_since(since)

    @staticmethod
    def get_decision_expiry_time(decision):
        return decision["created_at"] + timedelta(seconds=timeparse(decision["duration"]))


class MockLAPI:
    def __init__(self) -> None:
        self.app = Flask(__name__)
        self.app.add_url_rule("/v1/decisions/stream", view_func=self.decisions)
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        self.app.logger.disabled = True
        log.disabled = True
        self.ds = DataStore()

    def decisions(self):
        api_key = request.headers.get("x-api-key")
        if not api_key:
            abort(404)
        startup = True if request.args.get("startup") == "true" else False
        active_decisions, expired_decisions = self.ds.get_decisions_for_bouncer(api_key, startup)
        return {
            "new": formatted_decisions(active_decisions),
            "deleted": formatted_decisions(expired_decisions),
        }

    def start(self, port=8081):
        self.server_thread = ServerThread(self.app, port=port)
        self.server_thread.start()

    def stop(self):
        self.server_thread.shutdown()


def formatted_decisions(decisions):
    formatted_decisions = []
    for decision in decisions:
        expiry_time = decision["created_at"] + timedelta(seconds=timeparse(decision["duration"]))
        duration = expiry_time - datetime.datetime.now()
        formatted_decisions.append(
            {
                "duration": f"{duration.total_seconds()}s",
                "id": decision["id"],
                "origin": decision["origin"],
                "scenario": "cscli",
                "scope": decision["scope"],
                "type": decision["type"],
                "value": decision["value"],
            }
        )
    return formatted_decisions


# Copied from https://stackoverflow.com/a/45017691 .
# We run server inside thread instead of process to avoid
# huge complexity of sharing objects
class ServerThread(Thread):
    def __init__(self, app, port=8081):
        Thread.__init__(self)
        self.server = make_server("127.0.0.1", port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


if __name__ == "__main__":
    MockLAPI().start()
    sleep(100)
