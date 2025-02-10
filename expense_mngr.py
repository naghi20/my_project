import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
from datetime import datetime

# File to store expenses
EXPENSES_FILE = "expenses.json"

# Load existing expenses
def load_expenses():
    if os.path.exists(EXPENSES_FILE):
        with open(EXPENSES_FILE, "r") as file:
            return json.load(file)
    return []

# Save expenses to file
def save_expenses(expenses):
    with open(EXPENSES_FILE, "w") as file:
        json.dump(expenses, file)

# Add an expense
def add_expense():
    category = category_entry.get()
    amount = amount_entry.get()
    description = description_entry.get()
    date = date_entry.get()

    if not category or not amount or not description or not date:
        messagebox.showwarning("Input Error", "All fields are required!")
        return

    try:
        amount = float(amount)
        datetime.strptime(date, "%Y-%m-%d")  # Validate date format
    except ValueError:
        messagebox.showwarning("Input Error", "Invalid amount or date format (YYYY-MM-DD)!")
        return

    expenses = load_expenses()
    expenses.append({
        "category": category,
        "amount": amount,
        "description": description,
        "date": date
    })
    save_expenses(expenses)
    messagebox.showinfo("Success", "Expense added successfully!")
    update_expense_list()

# View all expenses
def view_expenses():
    expenses = load_expenses()
    expense_list.delete(0, tk.END)
    for expense in expenses:
        expense_list.insert(tk.END, f"{expense['date']} - {expense['category']}: ${expense['amount']} - {expense['description']}")

# Generate monthly report
def generate_monthly_report():
    month = simpledialog.askstring("Monthly Report", "Enter month (YYYY-MM):")
    if not month:
        return

    expenses = load_expenses()
    total = 0
    report = f"Monthly Report for {month}:\n\n"
    for expense in expenses:
        if expense['date'].startswith(month):
            total += expense['amount']
            report += f"{expense['date']} - {expense['category']}: ${expense['amount']} - {expense['description']}\n"

    report += f"\nTotal Expenses: ${total}"
    messagebox.showinfo("Monthly Report", report)

# Update expense list
def update_expense_list():
    view_expenses()
    category_entry.delete(0, tk.END)
    amount_entry.delete(0, tk.END)
    description_entry.delete(0, tk.END)
    date_entry.delete(0, tk.END)

# GUI Application
class ExpenseManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Expense Manager")
        self.create_widgets()

    def create_widgets(self):
        # Category
        tk.Label(self.root, text="Category:").grid(row=0, column=0, padx=10, pady=10)
        self.category_entry = tk.Entry(self.root, width=30)
        self.category_entry.grid(row=0, column=1, padx=10, pady=10)

        # Amount
        tk.Label(self.root, text="Amount:").grid(row=1, column=0, padx=10, pady=10)
        self.amount_entry = tk.Entry(self.root, width=30)
        self.amount_entry.grid(row=1, column=1, padx=10, pady=10)

        # Description
        tk.Label(self.root, text="Description:").grid(row=2, column=0, padx=10, pady=10)
        self.description_entry = tk.Entry(self.root, width=30)
        self.description_entry.grid(row=2, column=1, padx=10, pady=10)

        # Date
        tk.Label(self.root, text="Date (YYYY-MM-DD):").grid(row=3, column=0, padx=10, pady=10)
        self.date_entry = tk.Entry(self.root, width=30)
        self.date_entry.grid(row=3, column=1, padx=10, pady=10)

        # Add Expense Button
        tk.Button(self.root, text="Add Expense", command=add_expense).grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        # Expense List
        self.expense_list = tk.Listbox(self.root, width=50, height=10)
        self.expense_list.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        # View Expenses Button
        tk.Button(self.root, text="View Expenses", command=view_expenses).grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # Generate Monthly Report Button
        tk.Button(self.root, text="Generate Monthly Report", command=generate_monthly_report).grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# Main Application
if __name__ == "__main__":
    root = tk.Tk()
    app = ExpenseManagerApp(root)
    root.mainloop()
