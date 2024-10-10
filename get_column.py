import csv

# Replace 'file.csv' with your actual file path
with open('./outputCSV/output.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    # Get the first row which contains the column names
    column_names = next(reader)

print("Column names:", column_names)