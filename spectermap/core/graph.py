import networkx as nx
from sqlalchemy import select

from ..models import Asset, OpenPort, Relationship, Vulnerability
from .matcher import match_vulnerabilities, parse_banner


def build_graph(report):
    graph = nx.DiGraph()

    def node(key, kind, label, **details):
        graph.add_node(key, kind=kind, label=label, risk=0.0, details=details)
        return key

    root = node("host:" + report["host"], "domain", report["host"])
    for ip in report.get("ips", []):
        key = node("ip:" + ip, "ip", ip)
        graph.add_edge(root, key, kind="resolves_to")
    for page in report.get("pages", []):
        key = node("url:" + page["url"], "endpoint", page["url"], **page)
        graph.add_edge(root, key, kind="exposes")
        for document in page.get("documents", []):
            doc = node("doc:" + document, "document", document)
            graph.add_edge(key, doc, kind="links_to")
    for service in report.get("services", []):
        product, version = parse_banner(service["banner"])
        key = node(
            f"service:{service['port']}:{service['banner']}",
            "service",
            f"{service['port']} / {service['banner']}",
            **service,
            product=product,
            version=version,
        )
        # HTTP headers identify the virtual host, not every IP's independent service state.
        graph.add_edge(root, key, kind="advertises")
        for match in match_vulnerabilities(product, version):
            cve = node("cve:" + match["cve"], "cve", match["cve"], **match)
            graph.nodes[cve]["risk"] = match["severity"]
            graph.add_edge(key, cve, kind="candidate_for")
    for key in reversed(list(nx.topological_sort(graph))):
        children = [graph.nodes[child]["risk"] for child in graph.successors(key)]
        graph.nodes[key]["risk"] = max([graph.nodes[key]["risk"], *children])
    return graph


async def persist_graph(session, scan_id, graph):
    assets = {}
    for key, data in graph.nodes(data=True):
        asset = Asset(scan_id=scan_id, key=key, **data)
        session.add(asset)
        await session.flush()
        assets[key] = asset.id
        details = data["details"]
        if data["kind"] == "service":
            session.add(
                OpenPort(
                    asset_id=asset.id,
                    port=details["port"],
                    service=details["product"],
                    version=details["version"],
                )
            )
        if data["kind"] == "cve":
            session.add(
                Vulnerability(
                    asset_id=asset.id,
                    cve=details["cve"],
                    summary=details["summary"],
                    severity=details["severity"],
                    reference=details["reference"],
                )
            )
    for source, target, data in graph.edges(data=True):
        session.add(
            Relationship(source_id=assets[source], target_id=assets[target], kind=data["kind"])
        )


async def graph_elements(session, scan_id):
    assets = (await session.scalars(select(Asset).where(Asset.scan_id == scan_id))).all()
    ids = [asset.id for asset in assets]
    edges = (
        await session.scalars(select(Relationship).where(Relationship.source_id.in_(ids)))
    ).all()
    return {
        "nodes": [
            {
                "data": {
                    "id": str(a.id),
                    "label": a.label,
                    "kind": a.kind,
                    "risk": a.risk,
                    "details": a.details,
                }
            }
            for a in assets
        ],
        "edges": [
            {
                "data": {
                    "id": f"e{e.id}",
                    "source": str(e.source_id),
                    "target": str(e.target_id),
                    "label": e.kind,
                }
            }
            for e in edges
        ],
    }
