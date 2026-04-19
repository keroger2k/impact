import netaddr
from utils.ipam_engine import IPAMEngine, IPAMNode

def test_sorting():
    engine = IPAMEngine()
    # 10.10.0.0 and 10.2.0.0. Numerical: 10.2 < 10.10. ASCII: 10.1 < 10.2
    n1 = IPAMNode("10.10.0.0/24", source="ACI")
    n2 = IPAMNode("10.2.0.0/24", source="ACI")

    # roots 10.0.0.0/8
    root = IPAMNode("10.0.0.0/8", "Group")

    engine._insert_into_tree(root, n1)
    engine._insert_into_tree(root, n2)

    print(f"Children of {root.cidr}:")
    for c in root.children:
        print(f"  - {c.cidr}")

    assert root.children[0].cidr == "10.2.0.0/24"
    assert root.children[1].cidr == "10.10.0.0/24"
    print("Sorting test passed!")

if __name__ == "__main__":
    test_sorting()
