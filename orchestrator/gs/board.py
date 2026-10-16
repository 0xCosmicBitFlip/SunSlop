"""Which orchestrator owns a seat, and whether that seat is still live.

The cache is allowed to be empty. Ownership of a seat that has no live
owner is taken by the lowest live ordinal, and the activity time is the
newest stamp already known (the cache, or the pod annotation). A liveliness
update never changes the owner. Only the owner may reap, and only when the
newest stamp is older than the idle limit. Missing stamps wait out
claim_grace so a proxy can check in after a crash.
"""
import time

from gs.cache import Conflict, CacheDown


def ordinal_of(name):
    tail = (name or "").rsplit("-", 1)[-1]
    if tail.isdigit():
        return int(tail)
    return 1 << 30


def lowest_live(heartbeats, now, stale):
    live = [item for item in heartbeats if now - item["beat"] <= stale]
    if not live:
        return None
    live.sort(key=lambda item: (item["ordinal"], item["id"]))
    return live[0]


def _alive(owner, heartbeats, now, stale):
    for item in heartbeats:
        if item["id"] == owner and now - item["beat"] <= stale:
            return True
    return False


def plan_claims(me, heartbeats, seats, now, stale):
    """Seats whose owner is missing or dead. Only `me` if it is the lowest
    live instance. Each seat is {user, owner, activity, ann, node}."""
    winner = lowest_live(heartbeats, now, stale)
    if winner is None or winner["id"] != me:
        return []
    claims = []
    for seat in seats:
        owner = seat.get("owner") or ""
        if owner and _alive(owner, heartbeats, now, stale):
            continue
        activity = seat.get("activity")
        ann = seat.get("ann")
        if ann is not None and (activity is None or ann > activity):
            activity = ann
        claims.append({
            "user": seat["user"],
            "owner": me,
            "expect": owner,
            "activity": activity,
            "node": seat.get("node") or "",
            "claimed": now,
        })
    return claims


def should_reap(owner, activity, claimed, ann, me, now, idle, grace):
    if owner != me:
        return False
    newest = activity
    if ann is not None and (newest is None or ann > newest):
        newest = ann
    if newest is None:
        return now - (claimed if claimed is not None else now) >= grace
    return now - newest >= idle


class SeatBoard:
    def __init__(self, instance, cache, stale=15, grace=45, idle=600):
        self.me = instance
        self.ordinal = ordinal_of(instance)
        self.cache = cache
        self.stale = stale
        self.grace = grace
        self.idle = idle
        self.ready = False
        self._live = None
        self._live_since = None

    def _beat(self, now):
        self.cache.put(
            "orch/" + self.me,
            {"id": self.me, "ordinal": self.ordinal, "beat": now},
            now,
        )

    def _stable(self, live_ids, now):
        """True once this process has seen this same set of live orchestrators
        for a full stale interval. A wiped board makes every seat look
        ownerless, and the first process to notice would otherwise adopt
        them all before its peers have written a heartbeat."""
        if live_ids != self._live:
            self._live = live_ids
            self._live_since = now
            return False
        return now - self._live_since >= self.stale

    def reconcile(self, pods, now=None):
        """pods are {user, node, ann}. CacheDown leaves ready false."""
        now = time.time() if now is None else now
        try:
            self._beat(now)
            heartbeats = []
            for rec in self.cache.prefix("orch/").values():
                value = rec["value"]
                if value.get("id") and value.get("beat") is not None:
                    heartbeats.append(value)
            if not _alive(self.me, heartbeats, now, self.stale):
                self.ready = False
                return
            owners = self.cache.prefix("own/")
            acts = self.cache.prefix("act/")
            seats = []
            for pod in pods:
                user = pod.get("user") or ""
                if not user:
                    continue
                own = (owners.get("own/" + user) or {}).get("value") or {}
                act = (acts.get("act/" + user) or {}).get("value") or {}
                seats.append({
                    "user": user,
                    "owner": own.get("owner") or "",
                    "activity": act.get("activity"),
                    "ann": pod.get("ann"),
                    "node": pod.get("node") or "",
                })
            live_ids = tuple(sorted(
                item["id"] for item in heartbeats if now - item["beat"] <= self.stale
            ))
            blanks = [seat for seat in seats if not seat["owner"]]
            if (blanks or not seats) and not self._stable(live_ids, now):
                self.ready = False
                return
            for claim in plan_claims(self.me, heartbeats, seats, now, self.stale):
                self._claim(claim)
            self.ready = True
        except CacheDown:
            self.ready = False
            raise

    def _claim(self, claim):
        try:
            self.cache.put(
                "own/" + claim["user"],
                {
                    "owner": self.me,
                    "claimed": claim["claimed"],
                    "user": claim["user"],
                    "node": claim["node"],
                },
                claim["claimed"],
                expect_owner=claim["expect"],
            )
        except Conflict:
            return
        if claim["activity"] is None:
            return
        try:
            self.cache.put(
                "act/" + claim["user"],
                {"activity": claim["activity"], "user": claim["user"]},
                claim["activity"],
            )
        except Conflict:
            pass

    def own(self, user, node, now=None):
        """This process created the seat, so it becomes the owner."""
        now = time.time() if now is None else now
        self.cache.put(
            "own/" + user,
            {"owner": self.me, "claimed": now, "user": user, "node": node or ""},
            now,
        )
        self.cache.put("act/" + user, {"activity": now, "user": user}, now)

    def stamp(self, user, now=None):
        """Any orchestrator. Does not change who owns the seat."""
        now = time.time() if now is None else now
        self.cache.put("act/" + user, {"activity": now, "user": user}, now)

    def reapable(self, user, ann, now=None):
        now = time.time() if now is None else now
        own = self.cache.get("own/" + user)
        act = self.cache.get("act/" + user)
        if not own:
            return False
        value = own["value"]
        activity = None if not act else act["value"].get("activity")
        return should_reap(
            value.get("owner") or "",
            activity,
            value.get("claimed"),
            ann,
            self.me,
            now,
            self.idle,
            self.grace,
        )

    def drop(self, user):
        self.cache.delete("own/" + user)
        self.cache.delete("act/" + user)


def self_test():
    from gs.cache import KeyStore
    now = 10000.0
    store = KeyStore()
    low = SeatBoard("gs-orchestrator-0", store, stale=15, grace=45, idle=600)
    high = SeatBoard("gs-orchestrator-1", store, stale=15, grace=45, idle=600)
    pods = [{"user": "idle", "node": "n1", "ann": now - 5000}, {"user": "busy", "node": "n1", "ann": now - 5}]
    early = SeatBoard("gs-orchestrator-0", KeyStore(), stale=15, grace=45, idle=600)
    early.reconcile(pods, now=now + 1)
    assert early.ready is False
    # Empty board, both alive. The first look does not adopt, and the
    # higher ordinal does not adopt once the set has sat still.
    low.reconcile(pods, now=now)
    high.reconcile(pods, now=now)
    assert low.ready is False
    assert store.get("own/idle") is None
    low.reconcile(pods, now=now + 15)
    high.reconcile(pods, now=now + 15)
    assert store.get("own/idle") is None
    low.reconcile(pods, now=now + 30)
    high.reconcile(pods, now=now + 30)
    assert low.ready is True
    assert store.get("own/idle")["value"]["owner"] == "gs-orchestrator-0"
    assert store.get("act/idle")["value"]["activity"] == now - 5000
    assert store.get("own/busy")["value"]["owner"] == "gs-orchestrator-0"
    fresh = pods + [{"user": "fresh", "node": "n2", "ann": now + 31}]
    high.own("fresh", "n2", now=now + 31)
    low.reconcile(fresh, now=now + 31)
    assert store.get("own/fresh")["value"]["owner"] == "gs-orchestrator-1"
    high.stamp("busy", now=now + 32)
    assert store.get("own/busy")["value"]["owner"] == "gs-orchestrator-0"
    assert store.get("act/busy")["value"]["activity"] == now + 32
    assert low.reapable("idle", now - 5000, now=now + 32) is True
    assert low.reapable("busy", now - 5, now=now + 32) is False
    assert high.reapable("idle", now - 5000, now=now + 32) is False
    # Low's heartbeat is old. High adopts those seats and keeps its own.
    high.reconcile(
        [{"user": "idle", "node": "n1", "ann": now - 5000}, {"user": "busy", "node": "n1", "ann": now + 32},
         {"user": "fresh", "node": "n2", "ann": now + 31}],
        now=now + 50,
    )
    assert store.get("own/idle")["value"]["owner"] == "gs-orchestrator-1"
    assert store.get("own/fresh")["value"]["owner"] == "gs-orchestrator-1"
    assert high.reapable("busy", now + 32, now=now + 50) is False
    # Redis wiped, both processes still alive. They wait until both
    # heartbeats have been visible together, then the lower ordinal takes
    # the seats and keeps the pod's old activity time.
    for key in ("own/idle", "own/busy", "own/fresh", "act/idle", "act/busy", "act/fresh",
                "orch/gs-orchestrator-0", "orch/gs-orchestrator-1"):
        store.delete(key)
    wiped = [
        {"user": "idle", "node": "n1", "ann": now - 5000},
        {"user": "busy", "node": "n1", "ann": now + 32},
        {"user": "fresh", "node": "n2", "ann": now + 31},
    ]
    low.reconcile(wiped, now=now + 100)
    high.reconcile(wiped, now=now + 100)
    assert store.get("own/idle") is None
    assert low.ready is False
    low.reconcile(wiped, now=now + 115)
    high.reconcile(wiped, now=now + 115)
    low.reconcile(wiped, now=now + 130)
    assert store.get("own/idle")["value"]["owner"] == "gs-orchestrator-0"
    assert store.get("own/fresh")["value"]["owner"] == "gs-orchestrator-0"
    assert store.get("act/idle")["value"]["activity"] == now - 5000
    assert low.reapable("idle", now - 5000, now=now + 130) is True
    assert low.reapable("busy", now + 32, now=now + 130) is False
    naked = {"user": "new", "node": "n1", "ann": None}
    store2 = KeyStore()
    one = SeatBoard("gs-orchestrator-0", store2, stale=15, grace=45, idle=600)
    one.reconcile([naked], now=now)
    assert one.reapable("new", None, now=now + 10) is False
    one.reconcile([naked], now=now + 15)
    assert one.reapable("new", None, now=now + 25) is False
    assert one.reapable("new", None, now=now + 60) is True
    print("board self-test ok")

