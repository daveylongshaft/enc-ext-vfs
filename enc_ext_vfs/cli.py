import argparse
from enc_ext_vfs.vfs import VirtualFileSystem

def main():
    parser = argparse.ArgumentParser(description="Encrypted VFS Key and ACL Management Tool")
    parser.add_argument("storage_root", help="Path to the storage root directory")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create key
    create_parser = subparsers.add_parser("create-key", help="Create a new private key")
    create_parser.add_argument("owner", help="Owner of the key (username)")
    create_parser.add_argument("--name", default="", help="Friendly name for the key")
    create_parser.add_argument("--description", default="", help="Description of the key")

    # List keys
    list_parser = subparsers.add_parser("list-keys", help="List keys")
    list_parser.add_argument("--owner", help="Filter by owner username")

    # Grant access
    grant_parser = subparsers.add_parser("grant", help="Grant a user access to a key")
    grant_parser.add_argument("key_hash", help="The hash of the key")
    grant_parser.add_argument("owner", help="The owner of the key performing the grant")
    grant_parser.add_argument("user", help="The user to grant access to")

    # Revoke access
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a user's access to a key")
    revoke_parser.add_argument("key_hash", help="The hash of the key")
    revoke_parser.add_argument("owner", help="The owner of the key performing the revoke")
    revoke_parser.add_argument("user", help="The user to revoke access from")

    # List authorized users
    list_users_parser = subparsers.add_parser("list-users", help="List users authorized for a key")
    list_users_parser.add_argument("key_hash", help="The hash of the key")

    args = parser.parse_args()

    # Initialize VFS to get access to KeyManager and ACL
    vfs = VirtualFileSystem(args.storage_root)
    km = vfs._key_manager
    acl = vfs._key_manager._acl

    if args.command == "create-key":
        key_hash = km.register_key(args.owner, args.name, args.description)
        print(f"Key created successfully!")
        print(f"Key Hash: {key_hash}")
        print(f"Owner: {args.owner}")

    elif args.command == "list-keys":
        keys = km.list_keys(args.owner)
        if not keys:
            print("No keys found.")
        else:
            for k in keys:
                print(f"Hash: {k['hash']} | Owner: {k['owner']} | Name: '{k['name']}' | Desc: '{k['description']}'")

    elif args.command == "grant":
        try:
            km.authorize_user(args.key_hash, args.owner, args.user)
            print(f"Successfully granted '{args.user}' access to key '{args.key_hash}'.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "revoke":
        try:
            km.revoke_user(args.key_hash, args.owner, args.user)
            print(f"Successfully revoked '{args.user}' access from key '{args.key_hash}'.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "list-users":
        # Owner is always implicitly authorized, but acl.get_users() also shows explicitly granted users.
        users = acl.get_users(args.key_hash)
        metadata = km._keys.get(args.key_hash)
        if metadata:
            print(f"Owner: {metadata['owner']} (implicitly authorized)")
        if users:
            print(f"Explicitly authorized users: {', '.join(users)}")
        else:
            print("No explicitly authorized users.")

if __name__ == "__main__":
    main()
