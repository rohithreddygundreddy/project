from flask import Flask, render_template, request
import secrets

app = Flask(__name__)

A = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'o', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

# Converts alphanumeric characters to numbers of base 36
def f(x):
    store = []
    for s in x:
        count = 0
        for i in range(36):
            if A[i].lower() == s.lower():
                store.append(i)
                count = 1
                break
        if count == 0:
            store.append(' ')
    return tuple(store)

# Converts base 36 numbers to alphanumeric characters
def rf(x):
    store = []
    for s in x:
        try:
            store.append(A[s])
        except(IndexError, TypeError):
            store.append(' ')
    return ''.join(store)

# Generates a key without keyfile
def ikey(x):
    seed = list(range(36))
    masterkey = []
    for i in range(len(x)):
        masterkey.append(secrets.choice(seed))
    return tuple(masterkey)

# Encrypts a given string and returns ciphertext and key as a tuple (no file generated!)
def en(msg):
    ciphertxt = []
    x = f(msg)
    y = ikey(msg)
    for i in range(len(x)):
        if type(x[i]) is int:
            ciphertxt.append(((x[i] + y[i]) % 36))
        else:
            ciphertxt.append(' ')
    ctxt = rf(tuple(ciphertxt))
    shk = rf(y)
    return (ctxt, shk)

# Decrypts a given encrypted string and returns plaintext as output
def de(c, k):
    ciphertxt = []
    x = f(c)
    y = f(k)
    if len(x) <= len(y):
        for i in range(len(x)):
            if type(x[i]) is int and type(y[i]) is int:
                ciphertxt.append(((x[i] - y[i]) % 36))
            else:
                ciphertxt.append(' ')
    return rf(tuple(ciphertxt))

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    global n, message
    if request.method == 'POST':
        message = request.form['message']
        n = request.form['n']
        table = []
        x = int(n)
        msg = message
        table += list(en(msg))
        for i in range(2, x):
            tmp = table[-1]
            table.pop()
            table += list(en(tmp))
        return render_template('Encrypt.html', result=table)
    
    return render_template('Encrypt.html')

@app.route('/decrypt', methods=['POST', 'GET'])
def decrypt():
    global n, message, res
    msg = []
    if request.method == 'POST':
        n = request.form['n']
        msg.append(request.form['share1'])
        msg.append(request.form['share2'])
        msg.append(request.form['share3'])
        msg.append(request.form['share4'])
        msg.append(request.form['share5'])
        msg.append(request.form['share6'])
        msg.append(request.form['share7'])
        msg.append(request.form['share8'])
        msg.append(request.form['share9'])
        msg.append(request.form['share10'])

        x = int(n)
        table = []
        for i in range(x):
            table.append(str(msg[i]))
        for i in range(x - 1):
            hook = []
            a, b = table[-2], table[-1]
            table.pop()
            table.pop()
            hook.append(de(a, b))
            table += hook
        res = "".join(table)
        return render_template('Decrypt.html', result=res)
    return render_template('Decrypt.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # Update this as needed
