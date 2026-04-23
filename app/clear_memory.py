import argparse, shutil, os

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", required=True, help="U1, U2, U3, U4")
    args = ap.parse_args()
    tenant = args.tenant
    aliases = {"U1": "U1_genomics", "U2": "U2_nlp", "U3": "U3_robotics", "U4": "U4_materials"}
    root = os.path.join(".state", "memory", aliases.get(tenant, tenant))
    if os.path.exists(root):
        shutil.rmtree(root)
        print(f"Cleared memory for {args.tenant}")
    else:
        print(f"No memory state found for {args.tenant}")

if __name__ == "__main__":
    main()
