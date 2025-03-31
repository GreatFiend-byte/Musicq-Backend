require('dotenv').config();
const express = require("express");
const cors = require("cors");
const { db } = require("./firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require('multer');
const path = require('path');
const app = express();
const { OAuth2Client } = require('google-auth-library');

const saltRounds = 10;
const server_back = process.env.SERVER_BACK;
const server_front = process.env.SERVER_FRONT;
const port_b = process.env.PORT_B || 5001;
const port_f = process.env.PORT_F || 5173;
const client_id = process.env.GOOGLE_CLIENT_ID;
const client_secret = process.env.GOOGLE_CLIENT_SECRET;
const redirect_uri = process.env.GOOGLE_REDIRECT_URI;

const client = new OAuth2Client({
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI
});

const JWT_SECRET = crypto.randomBytes(32).toString("hex");
const nodemailer = require('nodemailer');


app.use(cors({
    origin: `http://${server_front}:${port_f}`,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    exposedHeaders: ['Authorization']
}));


app.use(express.json());


// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Token no proporcionado" });
    }


    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Token inválido o expirado" });
        }
        req.user = user;
        next();
    });
};

// Endpoint para registrar un nuevo usuario
app.post("/api/register", async (req, res) => {
    try {
        const { email, username, password, nombre, apellido, rol } = req.body;

        if (!email || !username || !password || !nombre || !apellido || !rol) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" });
        }
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const userRef = await db.collection("users").add({
            email,
            username,
            password: hashedPassword, 
            nombre,
            mfaEnabled: true,
            apellido,
            rol,
            createdAt: new Date(),
        });
        res.status(201).json({
            message: "Usuario registrado con éxito",
            userId: userRef.id,
        });
    } catch (error) {
        console.error("Error registrando usuario:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.post("/api/login", async (req, res) => {
    const { mfaVerification, mfaResend, email, code, tempToken, username, password } = req.body;
  
    try {
        if (mfaVerification) {
            if (!email || !code || !tempToken) {
                return res.status(400).json({
                    success: false,
                    message: "Email, código y token son requeridos para verificación MFA"
                });
            }
            
            return await handleMFACodeVerification(email, code, tempToken, res);
        } 
        else if (mfaResend) {
            if (!email || !tempToken) {
                return res.status(400).json({
                    success: false,
                    message: "Email y token son requeridos para reenviar código"
                });
            }
            return await handleMFAResend(email, tempToken, res);
        }
        else {
            if (!username || !password) {
                return res.status(400).json({ 
                    success: false,
                    message: "Usuario y contraseña son obligatorios" 
                });
            }
            return await handleRegularLogin(username, password, res);
        }
    } catch (error) {
        console.error("Error en el proceso de login:", error);
        
        if (error.name === 'MFARequiredError') {
            return res.status(200).json({
                success: true,
                mfaRequired: true,
                message: error.message,
                tempToken: error.tempToken,
                email: error.email
            });
        }
        
        return res.status(500).json({ 
            success: false,
            message: error.message || "Error interno del servidor" 
        });
    }
});

async function handleRegularLogin(username, password, res) {
    const usersRef = db.collection("users");
    const snapshot = await usersRef.where("username", "==", username).get();

    if (snapshot.empty) {
        throw new Error("Usuario no encontrado");
    }
    let userData;
    let userId;
    snapshot.forEach((doc) => {
        userData = doc.data();
        userId = doc.id;
    });

    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
        throw new Error("Contraseña incorrecta");
    }

    if (userData.mfaEnabled) {
        throw {
            name: 'MFARequiredError',
            message: "Se requiere verificación MFA",
            tempToken: await generateMFAToken(userId, userData.username, userData.email),
            email: userData.email
        };
    }

    return await generateAuthResponse(userId, userData, res);
}

async function handleMFACodeVerification(email, code, tempToken, res) {
    const decoded = jwt.verify(tempToken, JWT_SECRET);
    if (decoded.purpose !== "mfa-verification") {
        throw new Error("Token inválido");
    }
    const userId = decoded.userId;
    const mfaSnapshot = await db.collection("mfaCodes")
        .where("userId", "==", userId)
        .where("expiresAt", ">", new Date())
        .orderBy("expiresAt", "desc")
        .limit(1)
        .get();
    if (mfaSnapshot.empty) {
        throw new Error("Código expirado o no encontrado");
    }

    const mfaData = mfaSnapshot.docs[0].data();
    const isValid = await bcrypt.compare(code, mfaData.codeHash);
    if (!isValid) {
        throw new Error("Código inválido");
    }

    await db.collection("mfaCodes").doc(mfaSnapshot.docs[0].id).delete();

    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
        throw new Error("Usuario no encontrado");
    }

    const userData = userDoc.data();

    return await generateAuthResponse(userId, userData, res);
}

async function handleMFAResend(email, tempToken, res) {
    const decoded = jwt.verify(tempToken, JWT_SECRET);
    if (decoded.purpose !== "mfa-verification") {
        throw new Error("Token inválido");
    }

    const userId = decoded.userId;

    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
        throw new Error("Usuario no encontrado");
    }

    const userData = userDoc.data();

    await sendMFACode(userId, userData.email);

    return res.json({
        success: true,
        message: "Nuevo código de verificación enviado"
    });
}

async function sendMFACode(userId, email) {
    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = await bcrypt.hash(mfaCode, 10);
    
    const mfaRef = db.collection("mfaCodes").doc();
    await mfaRef.set({
        userId,
        codeHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), 
        createdAt: new Date()
    });

    const mailOptions = {
        from: `"Tu App" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Tu código de verificación MFA",
        html: `
            <div>
                <h2>Verificación en dos pasos</h2>
                <p>Tu código de verificación es: <strong>${mfaCode}</strong></p>
                <p>Este código expirará en 10 minutos.</p>
            </div>
        `
    };

    await transporter.sendMail(mailOptions);
}

async function generateMFAToken(userId, username, email) {
    const tempToken = jwt.sign(
        { 
            userId, 
            purpose: "mfa-verification",
            username
        }, 
        JWT_SECRET, 
        { expiresIn: "10m" }
    );

    await sendMFACode(userId, email);
    return tempToken;
}

async function generateAuthResponse(userId, userData, res) {
    const token = jwt.sign(
        { 
            userId, 
            username: userData.username,
            email: userData.email,
            rol: userData.rol 
        }, 
        JWT_SECRET, 
        { expiresIn: "1h" }
    );

    return res.json({
        success: true,
        message: "Autenticación exitosa",
        token,
        user: {
            id: userId,
            username: userData.username,
            email: userData.email,
            nombre: userData.nombre,
            apellido: userData.apellido,
            phone: userData.phone,
            birthDate: userData.birthDate,
            gender: userData.gender,
            rol: userData.rol,
            mfaEnabled: userData.mfaEnabled || false
        }
    });
}

app.get('/api/auth/google', (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_REDIRECT_URI) {
        throw new Error('Configuración de Google no definida');
    }
    const url = client.generateAuthUrl({
        access_type: 'offline',
        scope: ['profile', 'email'],
        prompt: 'select_account' // Obliga a seleccionar cuenta cada vez
    });
    res.json({ url });
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code } = req.query;

    try {
        // 1. Obtener tokens de Google
        const { tokens } = await client.getToken(code);

        // 2. Verificar el token ID
        const ticket = await client.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        
        const payload = ticket.getPayload();
        
        // 3. Crear objeto de usuario estandarizado
        const user = {
            id: payload.sub,
            email: payload.email,
            nombre: payload.name || `${payload.given_name} ${payload.family_name}`,
            avatar: payload.picture,
            // Agrega más campos si es necesario
            googleId: payload.sub,
            emailVerified: payload.email_verified
        };        

        const token = jwt.sign({userId: user.id, email: user.email}, JWT_SECRET, { expiresIn: "10m" });

        res.redirect(`${process.env.FRONTEND_URL}/login/success?token=${token}&user=${encodeURIComponent(JSON.stringify(user))}`);

    } catch (error) {
        console.error('Error en autenticación Google:', error);
        // Redirección directa a página de error
        res.redirect(`${process.env.FRONTEND_URL}/login/error?message=google_auth_failed&details=${encodeURIComponent(error.message)}`);
    }
});

app.get("/profile", authenticateToken, (req, res) => {
    res.json({
        message: "Acceso permitido",
        user: req.user,
    });
});

app.put("/api/profile", authenticateToken, async (req, res) => {
    try {
        const { nombre, apellido, username, email, phone, birthDate, gender } = req.body;

        // Validar campos obligatorios
        if (!nombre || !apellido || !username || !email) {
            return res.status(400).json({ message: "Nombre, apellido, username y email son obligatorios" });
        }

        const userId = req.user.userId || req.user.id; // Asegúrate de que el userId esté presente

        // Buscar usuario en Firestore
        const userDoc = await db.collection("users").doc(userId).get();
        if (!userDoc.exists) {
            return res.status(404).json({ message: "Usuario no encontrado" });
        }

        // Verificar si el nuevo username o email ya existen (excluyendo al usuario actual)
        const snapshot = await db.collection("users")
            .where('username', '==', username)
            .where('__name__', '!=', userId)
            .get();

        if (!snapshot.empty) {
            return res.status(400).json({ message: "El nombre de usuario ya está en uso" });
        }

        const emailSnapshot = await db.collection("users")
            .where('email', '==', email)
            .where('__name__', '!=', userId)
            .get();

        if (!emailSnapshot.empty) {
            return res.status(400).json({ message: "El email ya está en uso" });
        }

        // Preparar datos para actualización
        const updateData = {
            nombre,
            apellido,
            username,
            email,
            phone: phone || null,
            birthDate: birthDate || null,
            gender: gender || null,
            updatedAt: new Date()
        };

        // Actualizar usuario en Firestore
        await db.collection("users").doc(userId).update(updateData);

        // Obtener datos actualizados
        const updatedUserDoc = await db.collection("users").doc(userId).get();
        const updatedUser = updatedUserDoc.data();

        // Devolver respuesta exitosa
        res.status(200).json({
            message: "Perfil actualizado con éxito",
            user: {
                id: userId,
                nombre: updatedUser.nombre,
                apellido: updatedUser.apellido,
                username: updatedUser.username,
                email: updatedUser.email,
                phone: updatedUser.phone,
                birthDate: updatedUser.birthDate,
                gender: updatedUser.gender,
                rol: updatedUser.rol
            }
        });

    } catch (error) {
        console.error("Error actualizando perfil:", error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: "Token inválido" });
        }

        res.status(500).json({
            message: error.message || "Error interno del servidor"
        });
    }
});

// Configuración del transporter para nodemailer (usa tu servicio de correo)
const transporter = nodemailer.createTransport({
    service: 'gmail', // o otro servicio
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Agrega esta ruta para manejar la recuperación de contraseña
app.post("/api/request-password-reset", async (req, res) => {
    try {
        const { email, recaptchaToken } = req.body;

        // Verificar reCAPTCHA
        const recaptchaResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`
        });

        const recaptchaData = await recaptchaResponse.json();

        if (!recaptchaData.success) {
            return res.status(400).json({ message: "reCAPTCHA verification failed" });
        }

        // Buscar usuario por email
        const usersRef = db.collection("users");
        const snapshot = await usersRef.where("email", "==", email).get();

        if (snapshot.empty) {
            return res.status(404).json({ message: "No existe un usuario con este correo electrónico" });
        }

        // Obtener usuario
        let userData;
        let userId;
        snapshot.forEach((doc) => {
            userData = doc.data();
            userId = doc.id;
        });

        // Generar token
        const resetToken = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `http://${server_front}:${port_f}/reset-password?token=${resetToken}`;

        // Configuración del correo con diseño profesional
        const mailOptions = {
            from: `MusicQ <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Restablecimiento de contraseña - MusicQ',
            html: `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    background-color: #4a76a8;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }
                .content {
                    padding: 20px;
                    background-color: #f9f9f9;
                    border-radius: 0 0 5px 5px;
                    border: 1px solid #ddd;
                    border-top: none;
                }
                .button {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4a76a8;
                    color: white !important;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 15px 0;
                    font-weight: bold;
                }
                .footer {
                    margin-top: 20px;
                    font-size: 12px;
                    color: #777;
                    text-align: center;
                }
                .logo {
                    max-width: 150px;
                    margin-bottom: 15px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>MusicQ</h1>
                <h2>Restablecer contraseña</h2>
            </div>
            <div class="content">
                <p>Hola,</p>
                <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en MusicQ, tu tienda de instrumentos musicales.</p>
                
                <p>Para continuar con el proceso, haz clic en el siguiente botón:</p>
                
                <p style="text-align: center;">
                    <a href="${resetLink}" class="button">Restablecer contraseña</a>
                </p>
                
                <p>Si no solicitaste este cambio, puedes ignorar este mensaje. Tu contraseña permanecerá igual.</p>
                
                <p>Este enlace expirará en 1 hora por motivos de seguridad.</p>
                
                <p>Atentamente,<br>El equipo de MusicQ</p>
            </div>
            <div class="footer">
                <p>© ${new Date().getFullYear()} MusicQ - Todos los derechos reservados</p>
                <p>Este es un mensaje automático, por favor no respondas a este correo.</p>
            </div>
        </body>
        </html>
        `,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: "Se ha enviado un correo con instrucciones" });
    } catch (error) {
        console.error("Error en recuperación de contraseña:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Agrega esta ruta para manejar el restablecimiento de contraseña
app.post("/api/reset-password", async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Verificar token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Hashear nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Actualizar contraseña en la base de datos
        await db.collection("users").doc(decoded.userId).update({
            password: hashedPassword
        });

        res.status(200).json({ message: "Contraseña actualizada con éxito" });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(400).json({ message: "El enlace ha expirado" });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).json({ message: "Token inválido" });
        }
        console.error("Error al restablecer contraseña:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

app.put("/api/admin/user/:id", async (req, res) => {
    try {
        const { id } = req.params;
        let userData = req.body;

        if (!userData) {
            return res.status(400).json({ message: "Datos de usuario no proporcionados" });
        }

        // Si la contraseña está presente, encríptala antes de actualizarla
        if (userData.password) {
            const hashedPassword = await bcrypt.hash(userData.password, saltRounds);
            userData.password = hashedPassword; // Reemplaza la contraseña con la versión encriptada
        }

        // Actualizamos el usuario en la base de datos
        await db.collection("users").doc(id).update(userData);

        res.status(200).json({ message: "Usuario actualizado con éxito" });
    } catch (error) {
        console.error("Error actualizando usuario:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.delete("/api/admin/user/:id", async (req, res) => {
    try {
        const { id } = req.params;

        await db.collection("users").doc(id).delete();

        res.status(200).json({ message: "Usuario eliminado con éxito" });
    } catch (error) {
        console.error("Error eliminando usuario:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});



app.get("/api/category/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const categoriaRef = db.collection("categorias").doc(id);
        const categoriaDoc = await categoriaRef.get();

        if (!categoriaDoc.exists) {
            return res.status(404).json({ message: "Categoría no encontrada" });
        }

        let categoriaData = categoriaDoc.data();
        const instrumentosSnapshot = await categoriaRef.collection("instrumentos").get();

        let instrumentos = instrumentosSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.status(200).json({ id: categoriaDoc.id, ...categoriaData, instrumentos });
    } catch (error) {
        console.error("Error obteniendo la categoría:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


// Endpoint para obtener la lista de usuarios
app.get("/api/admin/users", async (req, res) => {
    try {
        const usersSnapshot = await db.collection("users").get();
        let users = [];

        usersSnapshot.forEach((doc) => {
            const userData = doc.data();
            users.push({
                id: doc.id,
                username: userData.username,
                email: userData.email,
                nombre: userData.nombre,
                apellido: userData.apellido,
                rol: userData.rol,
                password: userData.password,
                createdAt: userData.createdAt,
            });
        });

        res.status(200).json(users);
    } catch (error) {
        console.error("Error obteniendo la lista de usuarios:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.post("/api/category/:categoryId/instrument", async (req, res) => {
    try {
        const { categoryId } = req.params;
        const { descripcion, imagen, marca, nombre, precio, subcategoria, existencias } = req.body;

        if (!descripcion || !imagen || !marca || !nombre || !precio || !subcategoria || !existencias) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" });
        }

        const instrumentoRef = await db.collection("categorias").doc(categoryId).collection("instrumentos").add({
            descripcion,
            imagen,
            marca,
            nombre,
            precio,
            subcategoria,
            existencias,
            createdAt: new Date(),
        });

        res.status(201).json({
            message: "Instrumento creado con éxito",
            instrumentoId: instrumentoRef.id,
        });
    } catch (error) {
        console.error("Error creando instrumento:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

app.get("/api/categories", async (req, res) => {
    try {
        const categoriesSnapshot = await db.collection("categorias").get();

        if (categoriesSnapshot.empty) {
            return res.status(404).json({ message: "No se encontraron categorías" });
        }

        const categoriesWithInstruments = await Promise.all(categoriesSnapshot.docs.map(async (categoryDoc) => {
            const categoryData = categoryDoc.data();
            const categoryId = categoryDoc.id;

            const instrumentsSnapshot = await db.collection("categorias")
                .doc(categoryId)
                .collection("instrumentos")
                .get();

            const instruments = instrumentsSnapshot.empty
                ? [] 
                : instrumentsSnapshot.docs.map(instrumentDoc => {
                    const instrumentData = instrumentDoc.data();

                    const instrumentWithCategory = {
                        id: instrumentDoc.id,
                        categoryId, // 🔥 Se asegura que el ID de la categoría se agregue
                        ...instrumentData
                    };

                    return instrumentWithCategory;
                });

            return {
                id: categoryId,
                ...categoryData,
                instrumentos: instruments
            };
        }));

        res.status(200).json(categoriesWithInstruments);
    } catch (error) {
        console.error("Error obteniendo categorías e instrumentos:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.get("/api/category/:categoryId/instrument/:instrumentId", async (req, res) => {
    try {
        const { categoryId, instrumentId } = req.params;

        const instrumentoRef = db.collection("categorias").doc(categoryId).collection("instrumentos").doc(instrumentId);

        const instrumentoDoc = await instrumentoRef.get();

        if (!instrumentoDoc.exists) {
            return res.status(404).json({ message: "Instrumento no encontrado" });
        }

        const instrumento = instrumentoDoc.data();

        res.status(200).json({
            id: instrumentoDoc.id,
            ...instrumento,
        });
    } catch (error) {
        console.error("Error obteniendo el instrumento:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.put("/api/category/:categoryId/instrument/:instrumentId", async (req, res) => {
    try {
        const { categoryId, instrumentId } = req.params;
        const { descripcion, imagen, marca, nombre, precio, subcategoria, existencias } = req.body;

        if (!descripcion || !imagen || !marca || !nombre || !precio || !subcategoria || !existencias) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" });
        }

        const instrumentoRef = db.collection("categorias").doc(categoryId).collection("instrumentos").doc(instrumentId);

        await instrumentoRef.update({
            descripcion,
            imagen,
            marca,
            nombre,
            precio,
            subcategoria,
            existencias,
            updatedAt: new Date(),
        });

        res.status(200).json({ message: "Instrumento actualizado con éxito" });
    } catch (error) {
        console.error("Error actualizando instrumento:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

app.delete("/api/category/:categoryId/instrument/:instrumentId", async (req, res) => {
    try {
        const { categoryId, instrumentId } = req.params;

        const instrumentoRef = db.collection("categorias").doc(categoryId).collection("instrumentos").doc(instrumentId);

        await instrumentoRef.delete();

        res.status(200).json({ message: "Instrumento eliminado con éxito" });
    } catch (error) {
        console.error("Error eliminando instrumento:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.get("/api/products/:brand", async (req, res) => {
    try {
        const { brand } = req.params;

        if (!brand) {
            return res.status(400).json({ message: "El parámetro 'brand' es requerido" });
        }

        // Obtener todos los productos que coincidan con la marca
        const productsRef = db.collectionGroup("instrumentos"); // Busca en todas las subcolecciones "instrumentos"
        const snapshot = await productsRef.where("marca", "==", brand).get();

        const products = [];
        snapshot.forEach((doc) => {
            // Extraer el categoryId de la ruta del documento
            const path = doc.ref.path.split("/");
            const categoryId = path[1]; // El ID de la categoría está en la segunda posición de la ruta

            // Agregar el producto con el categoryId
            products.push({
                id: doc.id,
                categoryId: categoryId, // Incluir el categoryId
                ...doc.data(),
            });
        });

        //console.log(`productos enviados:`, products);
        res.status(200).json(products);
    } catch (error) {
        console.error("Error obteniendo productos por marca:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});



const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storage });

app.post('/upload', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    const imageUrl = `/uploads/${req.file.filename}`;

    res.json({ imageUrl });
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


app.get("/api/brands", async (req, res) => {
    try {
        const brandsRef = db.collection("brands");
        const snapshot = await brandsRef.get();
        const brands = [];
        snapshot.forEach(doc => {
            brands.push({ id: doc.id, ...doc.data() });
        });
        res.status(200).json(brands);
    } catch (error) {
        console.error("Error obteniendo marcas:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Agregar una nueva marca
app.post("/api/brands", async (req, res) => {
    try {
        const { nombre, descripcion } = req.body;
        const brandRef = await db.collection("brands").add({ nombre, descripcion });
        res.status(201).json({ id: brandRef.id, nombre, descripcion });
    } catch (error) {
        console.error("Error agregando marca:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Editar una marca existente
app.put("/api/brands/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, descripcion } = req.body;
        await db.collection("brands").doc(id).update({ nombre, descripcion });
        res.status(200).json({ id, nombre, descripcion });
    } catch (error) {
        console.error("Error editando marca:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Eliminar una marca
app.delete("/api/brands/:id", async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection("brands").doc(id).delete();
        res.status(200).json({ message: "Marca eliminada con éxito" });
    } catch (error) {
        console.error("Error eliminando marca:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Obtener todas las subcategorías
app.get("/api/subcategories", async (req, res) => {
    try {
        const subcategoriesRef = db.collection("subcategories");
        const snapshot = await subcategoriesRef.get();
        const subcategories = [];
        snapshot.forEach(doc => {
            subcategories.push({ id: doc.id, ...doc.data() });
        });
        res.status(200).json(subcategories);
    } catch (error) {
        console.error("Error obteniendo subcategorías:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Agregar una nueva subcategoría
app.post("/api/subcategories", async (req, res) => {
    try {
        const { nombre, descripcion } = req.body;
        const subcategoryRef = await db.collection("subcategories").add({ nombre, descripcion });
        res.status(201).json({ id: subcategoryRef.id, nombre, descripcion });
    } catch (error) {
        console.error("Error agregando subcategoría:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Editar una subcategoría existente
app.put("/api/subcategories/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, descripcion } = req.body;
        await db.collection("subcategories").doc(id).update({ nombre, descripcion });
        res.status(200).json({ id, nombre, descripcion });
    } catch (error) {
        console.error("Error editando subcategoría:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Eliminar una subcategoría
app.delete("/api/subcategories/:id", async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection("subcategories").doc(id).delete();
        res.status(200).json({ message: "Subcategoría eliminada con éxito" });
    } catch (error) {
        console.error("Error eliminando subcategoría:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


app.post("/api/orders", authenticateToken, async (req, res) => {
    const batch = db.batch();
    const orderData = req.body;

    try {
        if (!orderData.items || !orderData.shippingInfo || !orderData.total) {
            return res.status(400).json({ message: "Datos de orden incompletos" });
        }

        const inventoryUpdates = [];

        for (const item of orderData.items) {
            const instrumentRef = db.collection("categorias")
                .doc(item.categoryId)
                .collection("instrumentos")
                .doc(item.instrumentId);

            const instrumentDoc = await instrumentRef.get();

            if (!instrumentDoc.exists) {
                return res.status(404).json({
                    message: `Producto no encontrado: ${item.name}`
                });
            }

            const currentStock = instrumentDoc.data().existencias || 0;

            if (currentStock < item.quantity) {
                return res.status(400).json({
                    message: `Stock insuficiente para ${item.name}. Disponible: ${currentStock}, Solicitado: ${item.quantity}`
                });
            }

            inventoryUpdates.push({
                ref: instrumentRef,
                newStock: currentStock - item.quantity
            });
        }

        const newOrder = {
            ...orderData,
            userId: req.user.userId,
            status: "pending",
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const orderRef = db.collection("orders").doc();
        batch.set(orderRef, newOrder);

        for (const update of inventoryUpdates) {
            batch.update(update.ref, {
                existencias: update.newStock,
                updatedAt: new Date()
            });
        }

        await batch.commit();


        res.status(201).json({
            message: "Orden creada con éxito",
            orderId: orderRef.id
        });

    } catch (error) {
        console.error("Error creando orden:", error);

        if (error.code === 400) {
            return res.status(400).json({ message: error.message });
        }

        res.status(500).json({ message: "Error interno del servidor" });
    }
});

app.get("/api/orders/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const orderRef = db.collection("orders").doc(id);
        const orderDoc = await orderRef.get();

        if (!orderDoc.exists) {
            return res.status(404).json({ message: "Orden no encontrada" });
        }

        const orderData = orderDoc.data();

        // Verificar que el usuario tenga permiso para ver esta orden
        if (orderData.userId !== req.user.userId && req.user.rol !== "admin") {
            return res.status(403).json({ message: "No autorizado" });
        }

        res.status(200).json({
            id: orderDoc.id,
            ...orderData
        });
    } catch (error) {
        console.error("Error obteniendo orden:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


console.log("JWT_SECRET:", JWT_SECRET);
app.listen(port_b, () => {
    console.log(`Servidor corriendo en http://${server_back}:${port_b}`);
});