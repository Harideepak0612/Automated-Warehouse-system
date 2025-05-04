import requests

BASE_URL = "http://127.0.0.1:5000"

def add_item():
    name = input("Enter item name: ")
    quantity = int(input("Enter item quantity: "))
    category = input("Enter item category: ")
    threshold = int(input("Enter threshold quantity: "))

    data = {
        "name": name,
        "quantity": quantity,
        "category": category,
        "threshold": threshold
    }

    response = requests.post(f"{BASE_URL}/add_item", json=data)
    if response.status_code == 200:
        print("Item added successfully!")
    else:
        print("Error adding item:", response.json())

def get_inventory():
    response = requests.get(f"{BASE_URL}/get_inventory")
    if response.status_code == 200:
        inventory = response.json()
        if inventory:
            for item in inventory:
                print(f"Name: {item['name']}, Quantity: {item['quantity']}, Category: {item['category']}, Threshold: {item['threshold']}")
        else:
            print("No items in inventory.")
    else:
        print("Error fetching inventory:", response.json())

def update_item():
    name = input("Enter item name to update: ")
    quantity = int(input("Enter new quantity: "))

    data = {"quantity": quantity}

    response = requests.put(f"{BASE_URL}/update_item/{name}", json=data)
    if response.status_code == 200:
        print("Item updated successfully!")
    else:
        print("Error updating item:", response.json())

def delete_item():
    name = input("Enter item name to delete: ")

    response = requests.delete(f"{BASE_URL}/delete_item/{name}")
    if response.status_code == 200:
        print("Item deleted successfully!")
    else:
        print("Error deleting item:", response.json())

def low_stock():
    response = requests.get(f"{BASE_URL}/low_stock")
    if response.status_code == 200:
        inventory = response.json()
        if inventory:
            print("Low stock items:")
            for item in inventory:
                print(f"Name: {item['name']}, Quantity: {item['quantity']}, Threshold: {item['threshold']}")
        else:
            print("No low stock items.")
    else:
        print("Error checking low stock:", response.json())

def main():
    while True:
        print("\nInventory Management CLI")
        print("1. Add Item")
        print("2. View Inventory")
        print("3. Update Item Quantity")
        print("4. Delete Item")
        print("5. View Low Stock Items")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            add_item()
        elif choice == "2":
            get_inventory()
        elif choice == "3":
            update_item()
        elif choice == "4":
            delete_item()
        elif choice == "5":
            low_stock()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
