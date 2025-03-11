import tkinter as tk
from tkinter import ttk

window = tk.Tk()
# window.geometry('600x400+0+0')
# window.iconbitmap('python.ico')

window_width = 600
window_height = 400

display_width = window.winfo_screenwidth()
display_height = window.winfo_screenheight()

left = display_width // 2 - window_width // 2
top = display_height // 2 - window_height // 2
window.geometry(f'{window_width}x{window_height}+{left}+{top}')

# Window sizes
window.minsize(200, 100)
window.maxsize(800, 700)
window.resizable(True, True)

# Screen attributes
print(window.winfo_screenwidth())
print(window.winfo_screenheight())

# Window attributes
window.attributes('-alpha', 0.9) # Transparency
window.attributes('-topmost', True)

# Security event
window.bind('<Escape>', lambda event: window.quit())

# window.attributes('-fullscreen', True)

# Title bar
# window.overrideredirect(True)
grip = ttk.Sizegrip(window)
grip.place(relx=1.0, rely=1.0, anchor='se')

window.mainloop()