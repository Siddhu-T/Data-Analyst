# Data-Analyst
PRACTICAL LAB MANUAL - DEEP LEARNING
Student Name: Siddhesh Teli
Roll No: 18
Practical No. 1
Aim: Performing matrix multiplication and finding eigen vectors and eigen values using TensorFlow.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import tensorflow as tf
print('Matrix Multiplication Demo')
x = tf.constant([[1, 2, 3], [4, 5, 6]], dtype=tf.float32)
print ('Matrix X:\n', x)
y = tf.constant([[7,8], [9,10], [11, 12]], dtype=tf.float32)
print ("Matrix Y:\n", y)
z = tf.matmul(x,y)
print ("Product (x x Y):\n", z)
Eigenvalues and Eigenvectors
print("\n------- Siddhesh Teli ----- Roll No: 18	")
A = tf.constant([[1, 2], [5, 4]], dtype=tf.float32)
print("\nMatrix A:\n", A)
e_vals, e_vecs = tf.linalg.eigh(A)
print("\nEigenvalues:\n", e_vals)
print("\nEigenvectors:\n", e_vecs)
Practical No. 2
Aim: Solving XOR problem using deep feed forward network.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import numpy as np
import tensorflow as tf
model = tf.keras.Sequential([
tf.keras.layers.Dense(2, activation='relu', input_shape=(2,)),
tf.keras.layers.Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.summary()
x = np.array([[0.,0.], [0.,1.], [1.,0.], [1.,1]], dtype=float)
y = np.array([0.,1.,1.,0.], dtype=float)
model.fit(x, y, epochs=1000, batch_size=4, verbose=0)
print("\nWeights After training:")
print(model.get_weights())
print("\nPredictions:")
print(model.predict(x))
Practical No. 3
Aim: Implementing deep neural network for performing binary classification task.
Code:
print("------- Siddhesh Teli----- Roll No: 18	")
from keras.models import Sequential
from keras.layers import Dense
import pandas as pd
dataset = pd.read_csv('diabetes.csv')
print(dataset)
X = dataset.iloc[:,0:8]
Y = dataset.iloc[:,8]
print(X.shape, Y.shape)
model = Sequential()
model.add(Dense(12, input_shape=(8,), activation='relu'))
model.add(Dense(8, activation='relu'))
model.add(Dense(1, activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(X, Y, epochs=100, batch_size=10)
_, accuracy = model.evaluate(X, Y)
print('Accuracy:' ,(accuracy*100))
prediction = model.predict(X)
for i in range(5):
print(X.iloc[i].tolist(), prediction[i], Y.iloc[i])
Practical No. 4A
Aim: Using deep feed forward network with two hidden layers for performing multiclass classification and predicting the class.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import numpy as np
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelBinarizer
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
iris = load_iris()
X = iris.data
y = iris.target
lb = LabelBinarizer()
y = lb.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
model = Sequential()
model.add(Dense(16, activation='relu', input_shape=(4,)))
model.add(Dense(12, activation='relu'))
model.add(Dense(3, activation='softmax'))
model.compile(optimizer='adam', loss="categorical_crossentropy", metrics=['accuracy'])
model.fit(X_train, y_train, epochs=50, batch_size=8, verbose=1)
loss, accuracy = model.evaluate(X_test, y_test)
print("Test Accuracy:", accuracy)
new_sample = np.array([[5.1, 3.5, 1.4, 0.2]])
new_sample = scaler.transform(new_sample)
prediction = model.predict(new_sample)
print("Class Probabilities:", prediction)
print("Predicted Class:", lb.inverse_transform(prediction))
Practical No. 4B
Aim: Using a deep feed forward network with two hidden layers for performing classification and predicting the probability of class.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
from keras.models import Sequential
from keras.layers import Dense
from sklearn.datasets import make_blobs
from sklearn.preprocessing import MinMaxScaler
x, y = make_blobs(n_samples=100, centers=2, n_features=2, random_state=1)
scalar = MinMaxScaler()
scalar.fit(x)
x = scalar.transform(x)
model = Sequential()
model.add(Dense(4, input_shape=(2,), activation='relu'))
model.add(Dense(4, activation='relu'))
model.add(Dense(1, activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(x, y, epochs=500, verbose=0)
xnew, yreal = make_blobs(n_samples=3, centers=2, n_features=2, random_state=1)
xnew = scalar.transform(xnew)
ynew = model.predict(xnew)
for i in range(len(xnew)):
print("X-%s, Predicted-%s, Desired-%s" % (xnew[i], ynew[i], yreal[i]))
Practical No. 4C
Aim: Using a deep feed forward network with two hidden layers for performing linear regression and predicting values.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
from keras.models import Sequential
from keras.layers import Dense
from sklearn.datasets import make_regression
from sklearn.preprocessing import MinMaxScaler
x, y = make_regression(n_samples=100, n_features=2, noise=0.1, random_state=1)
scalarx, scalary = MinMaxScaler(), MinMaxScaler()
x = scalarx.fit_transform(x)
y = scalary.fit_transform(y.reshape(-1, 1))
model = Sequential()
model.add(Dense(4, input_shape=(2,), activation='relu'))
model.add(Dense(4, activation='relu'))
model.add(Dense(1, activation='linear'))
model.compile(loss='mse', optimizer='adam')
model.fit(x, y, epochs=500, batch_size=10, verbose=1)
xnew_generated_features, _ = make_regression(n_samples=3, n_features=2, noise=0.1, random_state=1)
xnew = scalarx.transform(xnew_generated_features)
ynew = model.predict(xnew)
for i in range(len(xnew)):
print("X=%s, Predicted (scaled)=%s" % (xnew[i], ynew[i]))
y_original = scalary.inverse_transform(ynew)
print("Actual Predicted Values:", y_original)
Practical No. 5A
Aim: Evaluating feed forward deep network for regression using KFold cross validation.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
from keras.models import Sequential
from keras.layers import Dense
from sklearn.model_selection import KFold
import numpy as np
load the data
dataset = np.genfromtxt("diabetes.csv", delimiter=",")
Split the data
x = dataset[:, 0:8]
y = dataset[:, 8]
Define kfold cross validation object
kfold = KFold(n_splits=5, shuffle=True)
Creating Model
model = Sequential()
model.add(Dense(12, input_dim=8, activation='relu'))
model.add(Dense(8, activation='relu'))
model.add(Dense(1, activation='sigmoid'))
Compiling Model
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
Model Evaluation
results = kfold.split(x)
for train_index, test_index in results:
x_train, x_test = x[train_index], x[test_index]
y_train, y_test = y[train_index], y[test_index]
model.fit(x_train, y_train, epochs=150, batch_size=10, verbose=0)
_, accuracy = model.evaluate(x_test, y_test)
print('Accuracy: %.2f' % (accuracy*100))
Practical No. 5B
Aim: Evaluating feed forward deep network for multiclass Classification using KFold cross-validation.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
from keras.models import Sequential
from keras.layers import Dense
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
Load Dataset
df = pd.read_csv('Flower.csv')
print(df.shape)
print(df.head(10))
print(df.describe())
Data cleaning
print(df.isnull().sum())
df.dropna(inplace=True)
EDA
sns.set_style('darkgrid')
sns.pairplot(df, hue="species")
plt.show()
corr_matrix = ["sepal_length", "sepal_width", "petal_length", "petal_width"]
sns.heatmap(df[corr_matrix].corr(), annot=True)
plt.title("correlation between values")
plt.show()
print(df.info())
typeofiris = df["species"].value_counts()
plt.pie(typeofiris, labels=typeofiris.index, autopct='%1.1f%%', startangle=90, colors=['lightblue', 'lightcoral','lightyellow'])
plt.title('Iris species distribution')
plt.show()
Data Preparation
y = pd.get_dummies(df['species'])
x = df.drop(['species'], axis=1)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3)
Building Model
model = Sequential()
model.add(Dense(4, input_shape=(4,), activation='relu'))
model.add(Dense(12, activation='sigmoid'))
model.add(Dense(3, activation='softmax'))
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
Train and Evaluate
model.fit(x_train, y_train, epochs=25, batch_size=3)
score = model.evaluate(x_test, y_test)
print("Test accuracy: ", score)
Prediction
class_names = ["Iris Setosa", "Iris Versicolor", "Iris Virginica"]
sample = np.array([[5.1, 3.5, 1.4, 0.2]])
p = model.predict(sample)
max_index = np.argmax(p)
print("Predicted Class :", class_names[max_index])
Practical No. 6
Aim: Implementing regularization to avoid overfitting in binary classification.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
from matplotlib import pyplot as plt
from sklearn.datasets import make_moons
from keras.models import Sequential
from keras.layers import Dense
from keras.regularizers import l1_l2
x, y = make_moons(n_samples=100, noise=0.2, random_state=1)
n_train = 30
trainx, testx = x[:n_train,:], x[n_train:]
trainy, testy = y[:n_train], y[n_train:]
model = Sequential()
model.add(Dense(500, input_dim=2, activation='relu', kernel_regularizer=l1_l2(l1=0.001, l2=0.001)))
model.add(Dense(1, activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
history = model.fit(trainx, trainy, validation_data=(testx, testy), epochs=1000)
plt.plot(history.history['val_accuracy'], label='test')
plt.legend()
plt.show()
Practical No. 7
Aim: Demonstrate recurrent neural network that learns to perform sequence analysis for stock price.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
1. Generate Dummy Stock Data
np.random.seed(1)
days = 200
price = np.cumsum(np.random.randn(days)) + 100
price = price.reshape(-1, 1)
2. Normalize the Data
scaler = MinMaxScaler(feature_range=(0, 1))
price_scaled = scaler.fit_transform(price)
3. Create Sequences
x, y = [], []
sequence_length = 10
for i in range(sequence_length, len(price_scaled)):
x.append(price_scaled[i-sequence_length:i])
y.append(price_scaled[i])
x, y = np.array(x), np.array(y)
4. Build RNN (LSTM) Model
model = Sequential()
model.add(LSTM(50, activation='tanh', input_shape=(x.shape[1], 1)))
model.add(Dense(1))
model.compile(optimizer='adam', loss='mean_squared_error')
5. Train the Model
model.fit(x, y, epochs=20, batch_size=16, verbose=1)
6. Predict Stock Prices
predicted_scaled = model.predict(x)
predicted = scaler.inverse_transform(predicted_scaled)
actual = scaler.inverse_transform(y)
7. Plot Results
plt.figure(figsize=(10, 5))
plt.plot(actual, label="Actual Stock Price")
plt.plot(predicted, label="Predicted Stock Price")
plt.title("RNN (LSTM) Stock Price Prediction")
plt.xlabel("Days")
plt.ylabel("Stock Price")
plt.legend()
plt.show()
Practical No. 8
Aim: Performing encoding and decoding of images using deep autoencoder.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import keras
from keras import layers
from keras.datasets import mnist
encoding_dim = 32
import numpy as np
import matplotlib.pyplot as plt
input_img = keras.Input(shape=(784,))
encode = layers.Dense(encoding_dim, activation='relu')(input_img)
decode = layers.Dense(784, activation='sigmoid')(encode)
autoencoder = keras.Model(input_img, decode)
encoder = keras.Model(input_img, encode)
encode_ip = keras.Input(shape=(encoding_dim,))
decoder_layer = autoencoder.layers[-1]
decoder = keras.Model(encode_ip, decoder_layer(encode_ip))
autoencoder.compile(optimizer='adam', loss='binary_crossentropy')
(x_train, _), (x_test, _) = mnist.load_data()
x_train = x_train.astype('float32') / 255
x_test = x_test.astype('float32') / 255
x_train = x_train.reshape((len(x_train), np.prod(x_train.shape[1:])))
x_test = x_test.reshape((len(x_test), np.prod(x_test.shape[1:])))
autoencoder.fit(x_train, x_train, epochs=50, batch_size=256, shuffle=True, validation_data=(x_test, x_test))
encoded_img = encoder.predict(x_test)
decoded_imgs = decoder.predict(encoded_img)
n = 10
plt.figure(figsize=(40,4))
for i in range(n):
ax = plt.subplot(3, 20, i + 1)
plt.imshow(x_test[i].reshape(28,28))
plt.gray()
ax.get_xaxis().set_visible(False)
ax.get_yaxis().set_visible(False)
ax = plt.subplot(3, 20, 2*20 + i - 1)
plt.imshow(decoded_imgs[i].reshape(28,28))
plt.gray()
ax.get_xaxis().set_visible(False)
ax.get_yaxis().set_visible(False)
plt.show()
Practical No. 9
Aim: Implementation of convolutional neural network to predict numbers from number images.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import numpy as np
import matplotlib.pyplot as plt
from tensorflow.keras.datasets import mnist
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout
from tensorflow.keras.utils import to_categorical
(X_train, y_train), (X_test, y_test) = mnist.load_data()
X_train = X_train / 255.0
X_test = X_test / 255.0
X_train = X_train.reshape(-1, 28, 28, 1)
X_test = X_test.reshape(-1, 28, 28, 1)
y_train = to_categorical(y_train, 10)
y_test = to_categorical(y_test, 10)
model = Sequential()
model.add(Conv2D(32, (3,3), activation='relu', input_shape=(28,28,1)))
model.add(MaxPooling2D((2,2)))
model.add(Conv2D(64, (3,3), activation='relu'))
model.add(MaxPooling2D((2,2)))
model.add(Flatten())
model.add(Dense(128, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(10, activation='softmax'))
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
history = model.fit(X_train, y_train, epochs=5, batch_size=128, validation_split=0.1)
test_loss, test_acc = model.evaluate(X_test, y_test)
print(f"Test accuracy: {test_acc:.4f}")
index = 3
prediction = model.predict(X_test[index].reshape(1,28,28,1))
predicted_digit = np.argmax(prediction)
plt.imshow(X_test[index].reshape(28,28), cmap='gray')
plt.title(f"Predicted Digit: {predicted_digit}")
plt.axis('off')
plt.show()
Practical No. 10
Aim: Denoising of images using autoencoder.
Code:
print("------- Siddhesh Teli ----- Roll No: 18	")
import numpy as np
import matplotlib.pyplot as plt
from tensorflow.keras.datasets import mnist
from tensorflow.keras.layers import Input, Dense, Flatten, Reshape
from tensorflow.keras.models import Model
1. Load and normalize data
(x_train, _), (x_test, _) = mnist.load_data()
x_train = x_train.astype('float32') / 255.
x_test = x_test.astype('float32') / 255.
x_train = x_train.reshape(-1, 28, 28, 1)
x_test = x_test.reshape(-1, 28, 28, 1)
2. Add noise
noise_factor = 0.5
x_train_noisy = x_train + noise_factor * np.random.normal(0.0, 1.0, x_train.shape)
x_test_noisy = x_test + noise_factor * np.random.normal(0.0, 1.0, x_test.shape)
x_train_noisy = np.clip(x_train_noisy, 0., 1.)
x_test_noisy = np.clip(x_test_noisy, 0., 1.)
3. Build Autoencoder
input_img = Input(shape=(28, 28, 1))
x = Flatten()(input_img)
x = Dense(128, activation='relu')(x)
x = Dense(64, activation='relu')(x)
x = Dense(128, activation='relu')(x)
x = Dense(28 * 28, activation='sigmoid')(x)
decoded = Reshape((28, 28, 1))(x)
autoencoder = Model(input_img, decoded)
autoencoder.compile(optimizer='adam', loss='binary_crossentropy')
4. Train the model
autoencoder.fit(x_train_noisy, x_train, epochs=10, batch_size=256, shuffle=True, validation_data=(x_test_noisy, x_test))
5. Denoise test images
decoded_imgs = autoencoder.predict(x_test_noisy)
6. Show results
n = 5
plt.figure(figsize=(10, 4))
for i in range(n):
plt.subplot(2, n, i + 1)
plt.imshow(x_test_noisy[i].reshape(28, 28), cmap='gray')
plt.title("Noisy")
plt.axis('off')
plt.subplot(2, n, i + 1 + n)
plt.imshow(decoded_imgs[i].reshape(28, 28), cmap='gray')
plt.title("Denoised")
plt.axis('off')
plt.tight_layout()
plt.show()

