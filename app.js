const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3006;
const JWT_SECRET = 'museum-secret-key-2025';

app.use(cors());
app.use(express.json());

// Правильные пути для статических файлов
app.use(express.static(path.join(__dirname, 'museum')));
app.use(express.static(path.join(__dirname, 'museum/html')));
app.use('/css', express.static(path.join(__dirname, 'museum/css')));
app.use('/js', express.static(path.join(__dirname, 'museum/js')));
app.use('/res', express.static(path.join(__dirname, 'museum/res')));

// Подключение к MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Pankidom104',
    database: 'museum',
    charset: 'utf8mb4'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        process.exit(1);
        return;
    }
    console.log('Connected to MySQL database');
});

// Middleware для аутентификации JWT токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Токен не предоставлен' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
};

// API для регистрации
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, email, phoneNumber, password } = req.body;
        console.log('Registration attempt for:', email);

        // Проверяем, существует ли пользователь с таким email
        const [existingUsers] = await db.promise().query(
            'SELECT user_id FROM User WHERE login = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Пользователь с таким email уже существует' 
            });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создаем пользователя в таблице User
        const [userResult] = await db.promise().execute(
            'INSERT INTO user (login, password, role, created_at) VALUES (?, ?, "visitor", NOW())',
            [email, hashedPassword]
        );

        const userId = userResult.insertId;

        // Создаем запись в таблице Visitor
        await db.promise().execute(
            'INSERT INTO visitor (user_id, first_name, last_name, email, phone_number, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
            [userId, firstName, lastName, email, phoneNumber || null]
        );

        // Создаем JWT токен
        const token = jwt.sign(
            { 
                userId: userId, 
                role: 'visitor',
                email: email,
                firstName: firstName,
                lastName: lastName
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            message: 'Регистрация успешна',
            token,
            user: {
                id: userId,
                role: 'visitor',
                email: email,
                firstName: firstName,
                lastName: lastName,
                isAdmin: false,
                isGuide: false
            }
        });

    } catch (error) {
        console.error('Registration API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка регистрации: ' + error.message 
        });
    }
});

// API для авторизации
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email);

        // Упрощенный запрос - ищем только в таблице User
        const [users] = await db.promise().query(`
            SELECT 
                u.user_id,
                u.login,
                u.password,
                u.role,
                v.first_name,
                v.last_name,
                v.email as visitor_email
            FROM user u
            LEFT JOIN Visitor v ON u.user_id = v.user_id
            WHERE u.login = ?
        `, [email]);

        console.log('Found users:', users.length);

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Пользователь не найден' });
        }

        const user = users[0];
        console.log('User found:', user);
        
        // Проверяем пароль с использованием bcrypt
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('Password valid:', isValidPassword);

        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Неверный пароль' });
        }

        // Создаем JWT токен
        const token = jwt.sign(
            { 
                userId: user.user_id, 
                role: user.role,
                email: user.login,
                firstName: user.first_name,
                lastName: user.last_name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            message: 'Авторизация успешна',
            token,
            user: {
                id: user.user_id,
                role: user.role,
                email: user.login,
                firstName: user.first_name,
                lastName: user.last_name,
                isAdmin: user.role === 'admin',
                isGuide: user.role === 'guide'
            }
        });

    } catch (error) {
        console.error('Login API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера: ' + error.message });
    }
});

// API для обновления профиля пользователя
app.post('/api/auth/update-profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, email, phoneNumber, currentPassword, newPassword } = req.body;
        const userId = req.user.userId;

        // Проверяем текущий пароль если меняются важные данные или пароль
        if (currentPassword && (newPassword || email !== req.user.email)) {
            const [users] = await db.promise().query(
                'SELECT password FROM user WHERE user_id = ?',
                [userId]
            );
            
            if (users.length === 0) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Пользователь не найден' 
                });
            }

            const isValidPassword = await bcrypt.compare(currentPassword, users[0].password);
            if (!isValidPassword) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Неверный текущий пароль' 
                });
            }
        }

        // Обновляем данные в таблице Visitor
        await db.promise().execute(
            'UPDATE visitor SET first_name = ?, last_name = ?, email = ?, phone_number = ? WHERE user_id = ?',
            [firstName, lastName, email, phoneNumber, userId]
        );

        // Обновляем email в таблице User если он изменился
        if (email !== req.user.email) {
            await db.promise().execute(
                'UPDATE user SET login = ? WHERE user_id = ?',
                [email, userId]
            );
        }

        // Обновляем пароль если предоставлен новый
        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await db.promise().execute(
                'UPDATE user SET password = ? WHERE user_id = ?',
                [hashedPassword, userId]
            );
        }

        // Получаем обновленные данные пользователя
        const [updatedUsers] = await db.promise().query(`
            SELECT 
                u.user_id,
                u.login,
                u.role,
                v.first_name,
                v.last_name,
                v.email,
                v.phone_number
            FROM user u
            JOIN visitor v ON u.user_id = v.user_id
            WHERE u.user_id = ?
        `, [userId]);

        const updatedUser = updatedUsers[0];

        // Обновляем JWT токен если изменились данные
        const newToken = jwt.sign(
            { 
                userId: updatedUser.user_id, 
                role: updatedUser.role,
                email: updatedUser.email,
                firstName: updatedUser.first_name,
                lastName: updatedUser.last_name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Профиль успешно обновлен',
            token: newToken,
            user: {
                id: updatedUser.user_id,
                role: updatedUser.role,
                email: updatedUser.email,
                firstName: updatedUser.first_name,
                lastName: updatedUser.last_name,
                phoneNumber: updatedUser.phone_number,
                isAdmin: updatedUser.role === 'admin',
                isGuide: updatedUser.role === 'guide'
            }
        });

    } catch (error) {
        console.error('Update profile API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления профиля: ' + error.message 
        });
    }
});

// API для получения данных текущего пользователя
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await db.promise().query(`
            SELECT 
                u.user_id,
                u.login,
                u.role,
                v.visitor_id,
                v.first_name,
                v.last_name,
                v.email,
                v.phone_number,
                g.guide_id,
                g.specialization,
                a.admin_id
            FROM user u
            LEFT JOIN visitor v ON u.user_id = v.user_id
            LEFT JOIN guide g ON u.user_id = g.user_id
            LEFT JOIN admin a ON u.user_id = a.user_id
            WHERE u.user_id = ?
        `, [req.user.userId]);

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Пользователь не найден' });
        }

        const user = users[0];
        res.json({
            success: true,
            user: {
                id: user.user_id,
                role: user.role,
                email: user.email || user.login,
                firstName: user.first_name,
                lastName: user.last_name,
                phoneNumber: user.phone_number,
                specialization: user.specialization,
                isAdmin: user.role === 'admin',
                isGuide: user.role === 'guide'
            }
        });
    } catch (error) {
        console.error('Get user API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API для получения бронирований пользователя
app.get('/api/bookings/my-bookings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Получаем заказы экскурсий
        const [tourBookings] = await db.promise().query(`
            SELECT 
                o.order_id,
                o.tour_time,
                o.visitors_count,
                o.status,
                o.price,
                o.audio_guide_rent,
                o.audio_guide_id,
                o.created_at,
                t.tour_name,
                t.tour_date,
                t.duration_minutes,
                'tour' as booking_type
            FROM orders o
            LEFT JOIN tour t ON o.tour_id = t.tour_id
            WHERE o.visitor_id = ?
        `, [visitorId]);

        // Получаем заказы выставок
        const [exhibitionBookings] = await db.promise().query(`
            SELECT 
                eo.order_id,
                eo.booking_time as tour_time,
                eo.visitors_count,
                eo.status,
                eo.price,
                0 as audio_guide_rent,
                NULL as audio_guide_id,
                eo.created_at,
                e.exhibition_name as tour_name,
                e.start_date as tour_date,
                0 as duration_minutes,
                'exhibition' as booking_type
            FROM exhibition_orders eo
            LEFT JOIN exhibition e ON eo.exhibition_id = e.exhibition_id
            WHERE eo.visitor_id = ?
        `, [visitorId]);

        // Получаем заказы мастер-классов
        const [masterclassBookings] = await db.promise().query(`
                       SELECT 
               mo.order_id,
               m.masterclass_date as tour_time,  -- время проведения мастер-класса
               mo.visitors_count,
               mo.status,
               mo.price,
               mo.created_at,
               m.masterclass_name as tour_name,
               m.masterclass_date as tour_date,  -- дата проведения мастер-класса
               m.duration_minutes,
               m.instructor_name,
               m.location,
               m.instructor_specialization,
               m.materials_included,
               m.skill_level,
               'masterclass' as booking_type
           FROM masterclass_orders mo
           LEFT JOIN masterclass m ON mo.masterclass_id = m.masterclass_id
           WHERE mo.visitor_id = ?
        `, [visitorId]);
        // Объединяем заказы
        const allBookings = [...tourBookings, ...exhibitionBookings, ...masterclassBookings];
        
        // Сортируем по дате создания
        allBookings.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json({ 
            success: true, 
            data: allBookings 
        });

    } catch (error) {
        console.error('My bookings API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки бронирований: ' + error.message 
        });
    }
});

// API для отмены бронирования
app.post('/api/bookings/cancel/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM Visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Пробуем отменить заказ экскурсии
        const [tourResult] = await db.promise().execute(
            'UPDATE orders SET status = "cancelled" WHERE order_id = ? AND visitor_id = ?',
            [orderId, visitorId]
        );

        // Если не нашли в заказах экскурсий, пробуем в заказах выставок
        if (tourResult.affectedRows === 0) {
            const [exhibitionResult] = await db.promise().execute(
                'UPDATE exhibition_orders SET status = "cancelled" WHERE order_id = ? AND visitor_id = ?',
                [orderId, visitorId]
            );

            if (exhibitionResult.affectedRows === 0) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Заказ не найден' 
                });
            }
        }

        res.json({ 
            success: true, 
            message: 'Заказ успешно отменен' 
        });

    } catch (error) {
        console.error('Cancel booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка отмены заказа: ' + error.message 
        });
    }
});

// API для бронирования мастер-класса
app.post('/api/bookings/book-masterclass', authenticateToken, async (req, res) => {
    try {
        const { masterclassId, visitorsCount, bookingTime } = req.body;
        const userId = req.user.userId;

        console.log('Masterclass booking request:', { masterclassId, visitorsCount, bookingTime });

        // Валидация обязательных полей
        if (!masterclassId || !visitorsCount || !bookingTime) {
            return res.status(400).json({ 
                success: false, 
                message: 'Не все обязательные поля заполнены' 
            });
        }

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM Visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Проверяем существование мастер-класса и получаем его данные
        const [masterclasses] = await db.promise().query(
            'SELECT masterclass_id, masterclass_name, price FROM masterclass WHERE masterclass_id = ?',
            [parseInt(masterclassId)]
        );

        if (masterclasses.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Мастер-класс не найден' 
            });
        }

        const masterclass = masterclasses[0];
        
        // Рассчитываем общую стоимость
        const totalPrice = parseFloat(masterclass.price || 0) * parseInt(visitorsCount);

        // Создаем заказ в таблице masterclass_orders (нужно создать таблицу)
        const [result] = await db.promise().execute(
            'INSERT INTO masterclass_orders (visitor_id, masterclass_id, price, booking_time, visitors_count, status, created_at) VALUES (?, ?, ?, ?, ?, "confirmed", NOW())',
            [visitorId, masterclassId, totalPrice, bookingTime, visitorsCount]
        );

        res.json({ 
            success: true, 
            message: 'Запись на мастер-класс успешно подтверждена',
            orderId: result.insertId,
            masterclass: {
                name: masterclass.masterclass_name,
                price: totalPrice
            }
        });

    } catch (error) {
        console.error('Masterclass booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка записи на мастер-класс: ' + error.message 
        });
    }
});
// API для создания нового заказа (бронирования)
app.post('/api/bookings/book', authenticateToken, async (req, res) => {
    try {
        const { tourId, visitorsCount, tourTime, audioGuideRent = false, guideId = null, guideType } = req.body;
        const userId = req.user.userId;

        console.log('Booking request:', { tourId, visitorsCount, tourTime, audioGuideRent, guideId, guideType });

        // Валидация обязательных полей
        if (!tourId || !visitorsCount || !tourTime) {
            return res.status(400).json({ 
                success: false, 
                message: 'Не все обязательные поля заполнены' 
            });
        }

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM Visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Проверяем существование тура и получаем его данные
        const [tours] = await db.promise().query(
            'SELECT tour_id, price, tour_name FROM tour WHERE tour_id = ?',
            [parseInt(tourId)]
        );

        if (tours.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Экскурсия не найдена' 
            });
        }

        const tour = tours[0];
        
        // Используем цену из базы данных
        let totalPrice = parseFloat(tour.price || 50) * parseInt(visitorsCount);

        // Добавляем стоимость в зависимости от типа сопровождения
        let audioGuideId = null;
        
        if (guideType === 'audio' && audioGuideRent) {
            totalPrice += 20 * parseInt(visitorsCount); // Стоимость аудиогида за человека
            
            // Назначаем доступный аудиогид
            const [audioGuides] = await db.promise().query(
                `SELECT audio_guide_id, device_number 
                 FROM audioguide 
                 WHERE status = 'available' AND battery_level > 20 
                 ORDER BY battery_level DESC 
                 LIMIT 1`
            );
            
            if (audioGuides.length > 0) {
                audioGuideId = audioGuides[0].audio_guide_id;
                
                // Обновляем статус аудиогида на "in_use"
                await db.promise().execute(
                    'UPDATE audioguide SET status = "in_use" WHERE audio_guide_id = ?',
                    [audioGuideId]
                );
            } else {
                return res.status(400).json({ 
                    success: false, 
                    message: 'К сожалению, сейчас нет доступных аудиогидов' 
                });
            }
        } else if (guideType === 'guide' && guideId) {
            totalPrice += 50; // Фиксированная стоимость за экскурсовода
            
            // Проверяем доступность экскурсовода
            const [guides] = await db.promise().query(
                'SELECT guide_id FROM guide WHERE guide_id = ? AND status = "active"',
                [guideId]
            );
            
            if (guides.length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Выбранный экскурсовод недоступен' 
                });
            }
        }

        // Подготавливаем параметры для запроса (используем только существующие колонки)
        const insertParams = [
            parseInt(visitorId), 
            parseInt(tourId), 
            parseFloat(totalPrice), 
            tourTime, 
            parseInt(visitorsCount), 
            (guideType === 'audio' && audioGuideRent) ? 1 : 0, 
            audioGuideId
        ];

        console.log('Insert params:', insertParams);

        // Создаем заказ в таблице orders (используем только существующие колонки)
        const [result] = await db.promise().execute(
            'INSERT INTO orders (visitor_id, tour_id, price, tour_time, visitors_count, audio_guide_rent, audio_guide_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, "confirmed", NOW())',
            insertParams
        );

        // Если выбран аудиогид, создаем запись в таблице аудиогидов
        if (guideType === 'audio' && audioGuideRent && audioGuideId) {
            await db.promise().execute(
                'INSERT INTO audioguiderental (visitor_id, audio_guide_id, rent_date, return_date, rental_fee, status, created_at) VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 1 DAY), ?, "active", NOW())',
                [visitorId, audioGuideId, 20 * parseInt(visitorsCount)]
            );
        }

        // Получаем созданный заказ с информацией
        const [newOrder] = await db.promise().query(`
            SELECT 
                o.*,
                t.tour_name,
                t.tour_date,
                t.duration_minutes
            FROM orders o
            LEFT JOIN tour t ON o.tour_id = t.tour_id
            WHERE o.order_id = ?
        `, [result.insertId]);

        res.json({ 
            success: true, 
            message: 'Экскурсия успешно забронирована',
            orderId: result.insertId,
            order: newOrder[0]
        });

    } catch (error) {
        console.error('Booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка бронирования: ' + error.message 
        });
    }
});

// API для создания пользователей (админ)
app.post('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const { firstName, lastName, email, phoneNumber, role, password } = req.body;

        // Проверяем существование пользователя
        const [existingUsers] = await db.promise().query(
            'SELECT user_id FROM user WHERE login = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Пользователь с таким email уже существует' 
            });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создаем пользователя
        const [userResult] = await db.promise().execute(
            'INSERT INTO user (login, password, role, created_at) VALUES (?, ?, ?, NOW())',
            [email, hashedPassword, role]
        );

        const userId = userResult.insertId;

        // Создаем запись в таблице Visitor
        await db.promise().execute(
            'INSERT INTO visitor (user_id, first_name, last_name, email, phone_number, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
            [userId, firstName, lastName, email, phoneNumber || null]
        );

        res.json({ 
            success: true, 
            message: 'Пользователь успешно создан',
            userId: userId
        });

    } catch (error) {
        console.error('Admin create user API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка создания пользователя: ' + error.message 
        });
    }
});

// API для обновления пользователей (админ)
app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const userId = req.params.id;
        const { firstName, lastName, email, phoneNumber, role, password } = req.body;

        console.log('Updating user:', { userId, firstName, lastName, email, role });

        // Проверяем существование пользователя
        const [existingUsers] = await db.promise().query(
            'SELECT user_id FROM user WHERE user_id = ?',
            [userId]
        );

        if (existingUsers.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Пользователь не найден' 
            });
        }

        // Обновляем данные в таблице Visitor
        await db.promise().execute(
            'UPDATE visitor SET first_name = ?, last_name = ?, email = ?, phone_number = ? WHERE user_id = ?',
            [firstName, lastName, email, phoneNumber, userId]
        );

        // Обновляем email и роль в таблице User
        await db.promise().execute(
            'UPDATE user SET login = ?, role = ? WHERE user_id = ?',
            [email, role, userId]
        );

        // Обновляем пароль если предоставлен новый
        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            await db.promise().execute(
                'UPDATE user SET password = ? WHERE user_id = ?',
                [hashedPassword, userId]
            );
        }

        res.json({ 
            success: true, 
            message: 'Пользователь успешно обновлен'
        });

    } catch (error) {
        console.error('Admin update user API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления пользователя: ' + error.message 
        });
    }
});

// API для создания экскурсии (админ)
app.post('/api/admin/tours', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const { tour_name, tour_date, tour_type, price, max_visitors, duration_minutes, status, hall_numbers, collection_id, guide_id } = req.body;

        console.log('Creating tour:', req.body);

        // Валидация обязательных полей
        if (!tour_name || !tour_date || !tour_type || !price) {
            return res.status(400).json({ 
                success: false, 
                message: 'Не все обязательные поля заполнены' 
            });
        }

        // Создаем экскурсию
        const [result] = await db.promise().execute(
            'INSERT INTO tour (tour_name, tour_date, tour_type, price, max_visitors, duration_minutes, status, hall_numbers, collection_id, guide_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
            [tour_name, tour_date, tour_type, price, max_visitors || 20, duration_minutes || 60, status || 'scheduled', hall_numbers, collection_id, guide_id]
        );

        res.json({ 
            success: true, 
            message: 'Экскурсия успешно создана',
            tourId: result.insertId
        });

    } catch (error) {
        console.error('Admin create tour API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка создания экскурсии: ' + error.message 
        });
    }
});

// API для обновления экскурсии (админ)
app.put('/api/admin/tours/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const tourId = req.params.id;
        const { tour_name, tour_date, tour_type, price, max_visitors, duration_minutes, status, hall_numbers, collection_id, guide_id } = req.body;

        console.log('Updating tour:', { tourId, ...req.body });

        // Проверяем существование экскурсии
        const [existingTours] = await db.promise().query(
            'SELECT tour_id FROM tour WHERE tour_id = ?',
            [tourId]
        );

        if (existingTours.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Экскурсия не найдена' 
            });
        }

        // Обработка пустых значений для обязательных полей
        const processedCollectionId = collection_id === '' ? null : collection_id;
        const processedGuideId = guide_id === '' ? null : guide_id;

        // Валидация обязательных полей
        if (!tour_name || !tour_date || !tour_type || price === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: 'Не все обязательные поля заполнены' 
            });
        }

        // Обновляем экскурсию
        await db.promise().execute(
            'UPDATE tour SET tour_name = ?, tour_date = ?, tour_type = ?, price = ?, max_visitors = ?, duration_minutes = ?, status = ?, hall_numbers = ?, collection_id = ?, guide_id = ? WHERE tour_id = ?',
            [
                tour_name, 
                tour_date, 
                tour_type, 
                parseFloat(price), 
                parseInt(max_visitors) || 20, 
                parseInt(duration_minutes) || 60, 
                status || 'scheduled', 
                hall_numbers || '', 
                processedCollectionId, 
                processedGuideId, 
                tourId
            ]
        );

        res.json({ 
            success: true, 
            message: 'Экскурсия успешно обновлена'
        });

    } catch (error) {
        console.error('Admin update tour API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления экскурсии: ' + error.message 
        });
    }
});
// API для получения коллекций (для выпадающего списка)
app.get('/api/admin/collections-list', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [collections] = await db.promise().query(`
            SELECT collection_id, collection_name 
            FROM collection 
            ORDER BY collection_name
        `);

        res.json({ success: true, data: collections });
    } catch (error) {
        console.error('Collections list API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки коллекций' });
    }
});

// API для получения экскурсоводов (для выпадающего списка)
app.get('/api/admin/guides-list', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [guides] = await db.promise().query(`
            SELECT guide_id, CONCAT(first_name, ' ', last_name) as full_name 
            FROM guide 
            WHERE status = 'active'
            ORDER BY first_name, last_name
        `);

        res.json({ success: true, data: guides });
    } catch (error) {
        console.error('Guides list API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки экскурсоводов' });
    }
});

// API для бронирования выставки
app.post('/api/bookings/book-exhibition', authenticateToken, async (req, res) => {
    try {
        const { exhibitionId, visitorsCount, bookingTime } = req.body;
        const userId = req.user.userId;

        console.log('Exhibition booking request:', { exhibitionId, visitorsCount, bookingTime });

        // Валидация обязательных полей
        if (!exhibitionId || !visitorsCount || !bookingTime) {
            return res.status(400).json({ 
                success: false, 
                message: 'Не все обязательные поля заполнены' 
            });
        }

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM Visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Проверяем существование выставки и получаем ее данные
        const [exhibitions] = await db.promise().query(
            'SELECT exhibition_id, exhibition_name, ticket_price FROM exhibition WHERE exhibition_id = ?',
            [parseInt(exhibitionId)]
        );

        if (exhibitions.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Выставка не найдена' 
            });
        }

        const exhibition = exhibitions[0];
        
        // Рассчитываем общую стоимость
        const totalPrice = parseFloat(exhibition.ticket_price || 0) * parseInt(visitorsCount);

        // Создаем заказ в таблице exhibition_orders
        const [result] = await db.promise().execute(
            'INSERT INTO exhibition_orders (visitor_id, exhibition_id, price, booking_time, visitors_count, status, created_at) VALUES (?, ?, ?, ?, ?, "confirmed", NOW())',
            [visitorId, exhibitionId, totalPrice, bookingTime, visitorsCount]
        );

        res.json({ 
            success: true, 
            message: 'Билет на выставку успешно забронирован',
            orderId: result.insertId,
            exhibition: {
                name: exhibition.exhibition_name,
                price: totalPrice
            }
        });

    } catch (error) {
        console.error('Exhibition booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка бронирования выставки: ' + error.message 
        });
    }
});
// API для получения деталей конкретного заказа
app.get('/api/bookings/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM Visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        const [orders] = await db.promise().query(`
            SELECT 
                o.order_id,
                o.tour_time,
                o.visitors_count,
                o.status,
                o.price,
                o.audio_guide_rent,
                o.audio_guide_id,
                o.created_at,
                t.tour_name,
                t.tour_date,
                t.duration_minutes,
                t.tour_type,
                t.hall_numbers,
                c.collection_name,
                CONCAT(g.first_name, ' ', g.last_name) as guide_name,
                g.phone_number as guide_phone,
                g.email as guide_email
            FROM orders o
            JOIN tour t ON o.tour_id = t.tour_id
            LEFT JOIN guide g ON t.guide_id = g.guide_id
            LEFT JOIN collection c ON t.collection_id = c.collection_id
            WHERE o.order_id = ? AND o.visitor_id = ?
        `, [orderId, visitorId]);

        if (orders.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Заказ не найден' 
            });
        }

        const order = orders[0];

        res.json({ 
            success: true, 
            data: {
                order_id: order.order_id,
                tour_time: order.tour_time,
                visitors_count: order.visitors_count,
                status: order.status,
                price: order.price,
                audio_guide_rent: order.audio_guide_rent,
                audio_guide_id: order.audio_guide_id,
                created_at: order.created_at,
                tour_name: order.tour_name,
                tour_date: order.tour_date,
                duration_minutes: order.duration_minutes,
                tour_type: order.tour_type,
                hall_numbers: order.hall_numbers,
                collection_name: order.collection_name,
                guide_name: order.guide_name,
                guide_phone: order.guide_phone,
                guide_email: order.guide_email
            }
        });

    } catch (error) {
        console.error('Get order details API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки деталей заказа: ' + error.message 
        });
    }
});
// API для получения доступных аудиогидов
app.get('/api/audioguides/available', async (req, res) => {
    try {
        const [audioGuides] = await db.promise().query(`
            SELECT 
                audio_guide_id,
                device_number,
                language,
                status,
                battery_level,
                last_maintenance_date
            FROM audioguide 
            WHERE status = 'available' AND battery_level > 20
            ORDER BY battery_level DESC, last_maintenance_date DESC
        `);

        res.json({ 
            success: true, 
            data: audioGuides 
        });

    } catch (error) {
        console.error('Available audioguides API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки аудиогидов' 
        });
    }
});
// API для получения экскурсий
app.get('/api/tours', async (req, res) => {
    try {
        console.log('Fetching tours from database...');
        const [tours] = await db.promise().query(`
            SELECT 
                t.tour_id,
                t.tour_name,
                t.tour_date,
                t.tour_type,
                t.hall_numbers,
                t.max_visitors,
                t.duration_minutes,
                t.price,
                t.status as tour_status,
                t.photo_url,
                t.photo_alt_text,
                t.photo_credit,
                c.collection_name,
                CONCAT(g.first_name, ' ', g.last_name) as guide_name
            FROM tour t
            JOIN collection c ON t.collection_id = c.collection_id
            LEFT JOIN guide g ON t.guide_id = g.guide_id
            WHERE t.tour_date >= CURDATE() AND t.status = 'scheduled'
            ORDER BY t.tour_date
        `);

        console.log(`Found ${tours.length} tours`);
        res.json({ success: true, data: tours });
    } catch (error) {
        console.error('Tours API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки экскурсий' });
    }
});

// API для получения деталей конкретного тура
app.get('/api/tours/:id', async (req, res) => {
    try {
        const tourId = req.params.id;
        console.log(`Fetching details for tour ${tourId}`);
        
        const [tours] = await db.promise().query(`
            SELECT 
                t.tour_id,
                t.tour_name,
                t.tour_date,
                t.tour_type,
                t.hall_numbers,
                t.max_visitors,
                t.duration_minutes,
                t.price,
                t.status as tour_status,
                t.photo_url,
                t.photo_alt_text,
                t.photo_credit,
                c.collection_name,
                CONCAT(g.first_name, ' ', g.last_name) as guide_name,
                g.guide_id
            FROM tour t
            JOIN collection c ON t.collection_id = c.collection_id
            LEFT JOIN guide g ON t.guide_id = g.guide_id
            WHERE t.tour_id = ?
        `, [tourId]);

        if (tours.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Экскурсия не найдена' 
            });
        }

        const tour = tours[0];
        
        // Форматируем дату для фронтенда
        const formattedTour = {
            ...tour,
            tour_date: new Date(tour.tour_date).toISOString()
        };

        res.json({ 
            success: true, 
            data: formattedTour 
        });

    } catch (error) {
        console.error('Tour details API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки деталей экскурсии' 
        });
    }
});

// API для создания экспоната (админ)
app.post('/api/admin/exhibits', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const { exhibit_name, creation_year, exhibit_type, condition_status, cost, collection_id } = req.body;

        console.log('Creating exhibit:', req.body);

        // Валидация обязательных полей
        if (!exhibit_name || !exhibit_type || !condition_status) {
            return res.status(400).json({ 
                success: false, 
                message: 'Название, тип и состояние экспоната обязательны' 
            });
        }

        // Обработка пустых значений
        const processedCollectionId = collection_id === '' ? null : collection_id;
        const processedCost = cost ? parseFloat(cost) : null;
        const processedCreationYear = creation_year ? parseInt(creation_year) : null;

        // Создаем экспонат БЕЗ description
        const [result] = await db.promise().execute(
            'INSERT INTO exhibit (exhibit_name, creation_year, exhibit_type, condition_status, cost, collection_id, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [exhibit_name, processedCreationYear, exhibit_type, condition_status, processedCost, processedCollectionId]
        );

        res.json({ 
            success: true, 
            message: 'Экспонат успешно создан',
            exhibitId: result.insertId
        });

    } catch (error) {
        console.error('Admin create exhibit API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка создания экспоната: ' + error.message 
        });
    }
});
// API для обновления экспоната (админ) 
app.put('/api/admin/exhibits/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const exhibitId = req.params.id;
        const { exhibit_name, creation_year, exhibit_type, condition_status, cost, collection_id } = req.body;

        console.log('Updating exhibit:', { exhibitId, ...req.body });

        // Проверяем существование экспоната
        const [existingExhibits] = await db.promise().query(
            'SELECT exhibit_id FROM exhibit WHERE exhibit_id = ?',
            [exhibitId]
        );

        if (existingExhibits.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Экспонат не найден' 
            });
        }

        // Обработка пустых значений
        const processedCollectionId = collection_id === '' ? null : collection_id;
        const processedCost = cost ? parseFloat(cost) : null;
        const processedCreationYear = creation_year ? parseInt(creation_year) : null;

        // Валидация обязательных полей
        if (!exhibit_name || !exhibit_type || !condition_status) {
            return res.status(400).json({ 
                success: false, 
                message: 'Название, тип и состояние экспоната обязательны' 
            });
        }

        // Обновляем экспонат БЕЗ description
        await db.promise().execute(
            'UPDATE exhibit SET exhibit_name = ?, creation_year = ?, exhibit_type = ?, condition_status = ?, cost = ?, collection_id = ? WHERE exhibit_id = ?',
            [exhibit_name, processedCreationYear, exhibit_type, condition_status, processedCost, processedCollectionId, exhibitId]
        );

        res.json({ 
            success: true, 
            message: 'Экспонат успешно обновлен'
        });

    } catch (error) {
        console.error('Admin update exhibit API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления экспоната: ' + error.message 
        });
    }
});
// API для создания коллекции (админ)
app.post('/api/admin/collections', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const { collection_name, creation_year } = req.body;
        console.log('Creating collection:', req.body);

        // Валидация обязательных полей
        if (!collection_name) {
            return res.status(400).json({ 
                success: false, 
                message: 'Название коллекции обязательно' 
            });
        }

        // Создаем коллекцию
        const [result] = await db.promise().execute(
            'INSERT INTO collection (collection_name, creation_year, created_at) VALUES (?, ?, NOW())',
            [collection_name, creation_year || null]
        );

        res.json({ 
            success: true, 
            message: 'Коллекция успешно создана',
            collectionId: result.insertId
        });

    } catch (error) {
        console.error('Admin create collection API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка создания коллекции: ' + error.message 
        });
    }
});
// API для обновления коллекции (админ)
app.put('/api/admin/collections/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const collectionId = req.params.id;
        const { collection_name, creation_year } = req.body;

        console.log('Updating collection:', { collectionId, ...req.body });

        // Проверяем существование коллекции
        const [existingCollections] = await db.promise().query(
            'SELECT collection_id FROM collection WHERE collection_id = ?',
            [collectionId]
        );

        if (existingCollections.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Коллекция не найдена' 
            });
        }

        // Валидация обязательных полей
        if (!collection_name) {
            return res.status(400).json({ 
                success: false, 
                message: 'Название коллекции обязательно' 
            });
        }

        // Обновляем коллекцию
        await db.promise().execute(
            'UPDATE collection SET collection_name = ?, creation_year = ? WHERE collection_id = ?',
            [collection_name, creation_year || null, collectionId]
        );

        res.json({ 
            success: true, 
            message: 'Коллекция успешно обновлена'
        });

    } catch (error) {
        console.error('Admin update collection API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления коллекции: ' + error.message 
        });
    }
});
// API для получения списка коллекций для выпадающего списка
app.get('/api/admin/collections-list', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [collections] = await db.promise().query(`
            SELECT collection_id, collection_name 
            FROM collection 
            ORDER BY collection_name
        `);

        res.json({ success: true, data: collections });
    } catch (error) {
        console.error('Collections list API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки коллекций' });
    }
});

// API для создания экскурсовода (админ)
app.post('/api/admin/guides', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const { first_name, last_name, phone_number, email, specialization, status } = req.body;

        console.log('Creating guide:', req.body);

        // Валидация обязательных полей
        if (!first_name || !last_name) {
            return res.status(400).json({ 
                success: false, 
                message: 'Имя и фамилия обязательны' 
            });
        }

        // Создаем экскурсовода
        const [result] = await db.promise().execute(
            'INSERT INTO guide (first_name, last_name, phone_number, email, specialization, status, hire_date, created_at) VALUES (?, ?, ?, ?, ?, ?, CURDATE(), NOW())',
            [first_name, last_name, phone_number || null, email || null, specialization || null, status || 'active']
        );

        res.json({ 
            success: true, 
            message: 'Экскурсовод успешно создан',
            guideId: result.insertId
        });

    } catch (error) {
        console.error('Admin create guide API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка создания экскурсовода: ' + error.message 
        });
    }
});

// API для обновления экскурсовода (админ)
app.put('/api/admin/guides/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const guideId = req.params.id;
        const { first_name, last_name, phone_number, email, specialization, status } = req.body;

        console.log('Updating guide:', { guideId, ...req.body });

        // Проверяем существование экскурсовода
        const [existingGuides] = await db.promise().query(
            'SELECT guide_id FROM guide WHERE guide_id = ?',
            [guideId]
        );

        if (existingGuides.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Экскурсовод не найден' 
            });
        }

        // Валидация обязательных полей
        if (!first_name || !last_name) {
            return res.status(400).json({ 
                success: false, 
                message: 'Имя и фамилия обязательны' 
            });
        }

        // Обновляем экскурсовода
        await db.promise().execute(
            'UPDATE guide SET first_name = ?, last_name = ?, phone_number = ?, email = ?, specialization = ?, status = ? WHERE guide_id = ?',
            [first_name, last_name, phone_number || null, email || null, specialization || null, status || 'active', guideId]
        );

        res.json({ 
            success: true, 
            message: 'Экскурсовод успешно обновлен'
        });

    } catch (error) {
        console.error('Admin update guide API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка обновления экскурсовода: ' + error.message 
        });
    }
});
// API для удаления экскурсоводов
app.delete('/api/admin/guides/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const guideId = req.params.id;
        
        // Проверяем, нет ли связанных экскурсий
        const [tours] = await db.promise().query(
            'SELECT COUNT(*) as count FROM tour WHERE guide_id = ?',
            [guideId]
        );
        
        if (tours[0].count > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Нельзя удалить экскурсовода, у которого есть назначенные экскурсии' 
            });
        }

        await db.promise().execute('DELETE FROM guide WHERE guide_id = ?', [guideId]);

        res.json({ success: true, message: 'Экскурсовод удален' });
    } catch (error) {
        console.error('Admin delete guide API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления экскурсовода: ' + error.message 
        });
    }
});
//получения выставок (экспонатов)
app.get('/api/exhibits', async (req, res) => {
    try {
        console.log('Fetching exhibits from database...');
        const [exhibits] = await db.promise().query(`
            SELECT 
                e.exhibit_id,
                e.exhibit_name,
                e.creation_year,
                e.exhibit_type,
                e.condition_status,
                e.cost,
                e.photo_url,
                e.photo_alt_text,
                e.photo_credit,
                e.additional_photos,
                c.collection_name
            FROM Exhibit e
            JOIN Collection c ON e.collection_id = c.collection_id
            ORDER BY e.exhibit_name
        `);

        console.log(`Found ${exhibits.length} exhibits`);
        res.json({ success: true, data: exhibits });
    } catch (error) {
        console.error('Exhibits API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки экспонатов' });
    }
});

// API для получения коллекций
app.get('/api/collections', async (req, res) => {
    try {
        console.log('Fetching collections from database...');
        const [collections] = await db.promise().query(`
            SELECT 
                c.collection_id,
                c.collection_name,
                c.creation_year,
                c.photo_url,
                c.photo_alt_text,
                c.photo_credit,
                c.banner_photo_url,
                COUNT(e.exhibit_id) as exhibit_count
            FROM Collection c
            LEFT JOIN Exhibit e ON c.collection_id = e.collection_id
            GROUP BY c.collection_id, c.collection_name, c.creation_year, 
                     c.photo_url, c.photo_alt_text, c.photo_credit, c.banner_photo_url
            ORDER BY c.collection_name
        `);

        console.log(`Found ${collections.length} collections`);
        res.json({ success: true, data: collections });
    } catch (error) {
        console.error('Collections API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки коллекций' });
    }
});

// API для получения заказов мастер-классов пользователя
app.get('/api/bookings/my-masterclass-bookings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Получаем заказы мастер-классов
        const [masterclassBookings] = await db.promise().query(`
            SELECT 
                mo.order_id,
                mo.booking_time,
                mo.visitors_count,
                mo.status,
                mo.price,
                mo.created_at,
                m.masterclass_name,
                m.masterclass_date,
                m.duration_minutes,
                m.instructor_name,
                m.location,
                m.instructor_specialization,
                m.materials_included,
                m.skill_level,
                'masterclass' as booking_type
            FROM masterclass_orders mo
            LEFT JOIN masterclass m ON mo.masterclass_id = m.masterclass_id
            WHERE mo.visitor_id = ?
            ORDER BY mo.created_at DESC
        `, [visitorId]);

        res.json({ 
            success: true, 
            data: masterclassBookings 
        });

    } catch (error) {
        console.error('My masterclass bookings API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки заказов мастер-классов: ' + error.message 
        });
    }
});


// API для получения выставок
app.get('/api/exhibitions', async (req, res) => {
    try {
        console.log('Fetching exhibitions from database...');
        const [exhibitions] = await db.promise().query(`
            SELECT 
                exhibition_id,
                exhibition_name,
                description,
                start_date,
                end_date,
                location,
                max_visitors,
                status,
                ticket_price,
                photo_url,
                banner_photo_url,
                photo_alt_text,
                photo_credit,
                additional_photos,
                collection_name,
                exhibits_count,
                days_remaining
            FROM exhibition_details
            ORDER BY start_date DESC
        `);

        console.log(`Found ${exhibitions.length} exhibitions`);
        res.json({ success: true, data: exhibitions });
    } catch (error) {
        console.error('Exhibitions API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки выставок' });
    }
});

// API для получения экскурсоводов
app.get('/api/guides', async (req, res) => {
    try {
        console.log('Fetching guides from database...');
        const [guides] = await db.promise().query(`
            SELECT 
                g.guide_id,
                g.last_name,
                g.first_name,
                g.phone_number,
                g.email,
                g.specialization,
                g.hire_date,
                g.status,
                g.photo_url,
                g.photo_alt_text,
                CONCAT(g.first_name, ' ', g.last_name) as full_name,
                TIMESTAMPDIFF(YEAR, g.hire_date, CURDATE()) as experience_years,
                COUNT(t.tour_id) as tours_count
            FROM Guide g
            LEFT JOIN Tour t ON g.guide_id = t.guide_id AND t.tour_date >= CURDATE()
            WHERE g.status = 'active'
            GROUP BY g.guide_id
            ORDER BY g.last_name, g.first_name
        `);

        console.log(`Found ${guides.length} guides`);
        res.json({ success: true, data: guides });
    } catch (error) {
        console.error('Guides API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки экскурсоводов' });
    }
});

// API для отмены заказа мастер-класса
app.post('/api/bookings/cancel-masterclass/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Отменяем заказ мастер-класса
        const [result] = await db.promise().execute(
            'UPDATE masterclass_orders SET status = "cancelled" WHERE order_id = ? AND visitor_id = ?',
            [orderId, visitorId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Заказ мастер-класса не найден' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Заказ мастер-класса успешно отменен' 
        });

    } catch (error) {
        console.error('Cancel masterclass booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка отмены заказа мастер-класса: ' + error.message 
        });
    }
});

// API для получения экспонатов конкретной коллекции
app.get('/api/collections/:id/exhibits', async (req, res) => {
    try {
        const collectionId = req.params.id;
        console.log(`Fetching exhibits for collection ${collectionId}`);
        
        const [exhibits] = await db.promise().query(`
            SELECT 
                e.exhibit_id,
                e.exhibit_name,
                e.creation_year,
                e.exhibit_type,
                e.condition_status,
                e.cost
            FROM Exhibit e
            WHERE e.collection_id = ?
            ORDER BY e.exhibit_name
        `, [collectionId]);

        console.log(`Found ${exhibits.length} exhibits for collection ${collectionId}`);
        res.json({ success: true, data: exhibits });
    } catch (error) {
        console.error('Collection exhibits API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки экспонатов' });
    }
});

// API для получения мастер-классов
app.get('/api/masterclasses', async (req, res) => {
    try {
        console.log('Fetching masterclasses from database...');
        const [masterclasses] = await db.promise().query(`
            SELECT 
                masterclass_id,
                masterclass_name,
                description,
                masterclass_date,
                duration_minutes,
                max_participants,
                price,
                instructor_name,
                instructor_specialization,
                location,
                materials_included,
                skill_level,
                status,
                photo_url,
                photo_alt_text,
                photo_credit,
                additional_photos,
                days_until
            FROM masterclass_details
            ORDER BY masterclass_date
        `);

        console.log(`Found ${masterclasses.length} masterclasses`);
        res.json({ success: true, data: masterclasses });
    } catch (error) {
        console.error('Masterclasses API error:', error);
        res.status(500).json({ success: false, message: 'Ошибка загрузки мастер-классов' });
    }
});

// API для отмены заказа выставки
app.post('/api/bookings/cancel-exhibition/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;
        const userId = req.user.userId;

        // Сначала получаем visitor_id по user_id
        const [visitors] = await db.promise().query(
            'SELECT visitor_id FROM visitor WHERE user_id = ?',
            [userId]
        );

        if (visitors.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Посетитель не найден' 
            });
        }

        const visitorId = visitors[0].visitor_id;

        // Отменяем заказ выставки
        const [result] = await db.promise().execute(
            'UPDATE exhibition_orders SET status = "cancelled" WHERE order_id = ? AND visitor_id = ?',
            [orderId, visitorId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Заказ выставки не найден' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Заказ выставки успешно отменен' 
        });

    } catch (error) {
        console.error('Cancel exhibition booking API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка отмены заказа выставки: ' + error.message 
        });
    }
});

// API для админ-панели - Получение пользователей
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        console.log('Admin users API called by user:', req.user.userId, 'role:', req.user.role);
        
        // Проверяем права администратора
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [users] = await db.promise().query(`
            SELECT 
                u.user_id,
                u.login as email,
                u.role,
                u.created_at,
                v.first_name,
                v.last_name,
                v.phone_number
            FROM user u
            LEFT JOIN visitor v ON u.user_id = v.user_id
            ORDER BY u.created_at DESC
        `);

        console.log(`Found ${users.length} users for admin`);
        res.json({ success: true, data: users });
    } catch (error) {
        console.error('Admin users API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки пользователей: ' + error.message 
        });
    }
});

// API для админ-панели - Получение экскурсий
app.get('/api/admin/tours', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [tours] = await db.promise().query(`
            SELECT 
                t.tour_id,
                t.tour_name,
                t.tour_date,
                t.tour_type,
                t.hall_numbers,
                t.max_visitors,
                t.duration_minutes,
                t.price,
                t.status,
                t.created_at,
                c.collection_name,
                CONCAT(g.first_name, ' ', g.last_name) as guide_name
            FROM tour t
            LEFT JOIN collection c ON t.collection_id = c.collection_id
            LEFT JOIN guide g ON t.guide_id = g.guide_id
            ORDER BY t.tour_date DESC
        `);

        console.log(`Found ${tours.length} tours for admin`);
        res.json({ success: true, data: tours });
    } catch (error) {
        console.error('Admin tours API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки экскурсий: ' + error.message 
        });
    }
});

// API для админ-панели - Получение экспонатов
app.get('/api/admin/exhibits', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [exhibits] = await db.promise().query(`
            SELECT 
                e.exhibit_id,
                e.exhibit_name,
                e.creation_year,
                e.exhibit_type,
                e.condition_status,
                e.cost,
                e.created_at,
                c.collection_name
            FROM exhibit e
            LEFT JOIN collection c ON e.collection_id = c.collection_id
            ORDER BY e.exhibit_name
        `);

        console.log(`Found ${exhibits.length} exhibits for admin`);
        res.json({ success: true, data: exhibits });
    } catch (error) {
        console.error('Admin exhibits API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки экспонатов: ' + error.message 
        });
    }
});

// API для админ-панели - Получение коллекций
app.get('/api/admin/collections', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [collections] = await db.promise().query(`
            SELECT 
                c.collection_id,
                c.collection_name,
                c.creation_year,
                c.created_at,
                COUNT(e.exhibit_id) as exhibit_count
            FROM collection c
            LEFT JOIN exhibit e ON c.collection_id = e.collection_id
            GROUP BY c.collection_id, c.collection_name, c.creation_year, c.created_at
            ORDER BY c.collection_name
        `);

        console.log(`Found ${collections.length} collections for admin`);
        res.json({ success: true, data: collections });
    } catch (error) {
        console.error('Admin collections API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки коллекций: ' + error.message 
        });
    }
});

// API для админ-панели - Получение экскурсоводов
app.get('/api/admin/guides', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [guides] = await db.promise().query(`
            SELECT 
                g.guide_id,
                g.first_name,
                g.last_name,
                g.phone_number,
                g.email,
                g.specialization,
                g.hire_date,
                g.status,
                g.created_at
            FROM guide g
            ORDER BY g.last_name, g.first_name
        `);

        console.log(`Found ${guides.length} guides for admin`);
        res.json({ success: true, data: guides });
    } catch (error) {
        console.error('Admin guides API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки экскурсоводов: ' + error.message 
        });
    }
});

// API для админ-панели - Получение выставок
app.get('/api/admin/exhibitions', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [exhibitions] = await db.promise().query(`
            SELECT 
                e.exhibition_id,
                e.exhibition_name,
                e.description,
                e.start_date,
                e.end_date,
                e.location,
                e.max_visitors,
                e.status,
                e.ticket_price,
                e.created_at,
                c.collection_name
            FROM exhibition e
            LEFT JOIN collection c ON e.collection_id = c.collection_id
            ORDER BY e.start_date DESC
        `);

        console.log(`Found ${exhibitions.length} exhibitions for admin`);
        res.json({ success: true, data: exhibitions });
    } catch (error) {
        console.error('Admin exhibitions API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки выставок: ' + error.message 
        });
    }
});

// API для админ-панели - Получение мастер-классов
app.get('/api/admin/masterclasses', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const [masterclasses] = await db.promise().query(`
            SELECT 
                m.masterclass_id,
                m.masterclass_name,
                m.description,
                m.masterclass_date,
                m.duration_minutes,
                m.max_participants,
                m.price,
                m.instructor_name,
                m.instructor_specialization,
                m.location,
                m.materials_included,
                m.skill_level,
                m.status,
                m.created_at
            FROM masterclass m
            ORDER BY m.masterclass_date DESC
        `);

        console.log(`Found ${masterclasses.length} masterclasses for admin`);
        res.json({ success: true, data: masterclasses });
    } catch (error) {
        console.error('Admin masterclasses API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка загрузки мастер-классов: ' + error.message 
        });
    }
});

// API для удаления пользователей
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const userId = req.params.id;

        // Проверяем, что пользователь не удаляет сам себя
        if (parseInt(userId) === req.user.userId) {
            return res.status(400).json({ success: false, message: 'Нельзя удалить собственный аккаунт' });
        }

        // Начинаем транзакцию для безопасного удаления
        await db.promise().execute('DELETE FROM visitor WHERE user_id = ?', [userId]);
        await db.promise().execute('DELETE FROM user WHERE user_id = ?', [userId]);

        res.json({ success: true, message: 'Пользователь удален' });
    } catch (error) {
        console.error('Admin delete user API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления пользователя: ' + error.message 
        });
    }
});

// API для удаления экскурсий
app.delete('/api/admin/tours/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const tourId = req.params.id;
        await db.promise().execute('DELETE FROM tour WHERE tour_id = ?', [tourId]);

        res.json({ success: true, message: 'Экскурсия удалена' });
    } catch (error) {
        console.error('Admin delete tour API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления экскурсии: ' + error.message 
        });
    }
});

// API для удаления экспонатов
app.delete('/api/admin/exhibits/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const exhibitId = req.params.id;
        await db.promise().execute('DELETE FROM exhibit WHERE exhibit_id = ?', [exhibitId]);

        res.json({ success: true, message: 'Экспонат удален' });
    } catch (error) {
        console.error('Admin delete exhibit API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления экспоната: ' + error.message 
        });
    }
});

// API для удаления коллекций
app.delete('/api/admin/collections/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const collectionId = req.params.id;
        
        // Проверяем, нет ли связанных экспонатов
        const [exhibits] = await db.promise().query(
            'SELECT COUNT(*) as count FROM exhibit WHERE collection_id = ?',
            [collectionId]
        );
        
        if (exhibits[0].count > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Нельзя удалить коллекцию, в которой есть экспонаты' 
            });
        }

        await db.promise().execute('DELETE FROM collection WHERE collection_id = ?', [collectionId]);

        res.json({ success: true, message: 'Коллекция удалена' });
    } catch (error) {
        console.error('Admin delete collection API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления коллекции: ' + error.message 
        });
    }
});

// API для удаления экскурсоводов
app.delete('/api/admin/guides/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const guideId = req.params.id;
        
        // Проверяем, нет ли связанных экскурсий
        const [tours] = await db.promise().query(
            'SELECT COUNT(*) as count FROM tour WHERE guide_id = ?',
            [guideId]
        );
        
        if (tours[0].count > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Нельзя удалить экскурсовода, у которого есть назначенные экскурсии' 
            });
        }

        await db.promise().execute('DELETE FROM guide WHERE guide_id = ?', [guideId]);

        res.json({ success: true, message: 'Экскурсовод удален' });
    } catch (error) {
        console.error('Admin delete guide API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления экскурсовода: ' + error.message 
        });
    }
});

// API для удаления выставок
app.delete('/api/admin/exhibitions/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const exhibitionId = req.params.id;
        await db.promise().execute('DELETE FROM exhibition WHERE exhibition_id = ?', [exhibitionId]);

        res.json({ success: true, message: 'Выставка удалена' });
    } catch (error) {
        console.error('Admin delete exhibition API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления выставки: ' + error.message 
        });
    }
});

// API для удаления мастер-классов
app.delete('/api/admin/masterclasses/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещен' });
        }

        const masterclassId = req.params.id;
        await db.promise().execute('DELETE FROM masterclass WHERE masterclass_id = ?', [masterclassId]);

        res.json({ success: true, message: 'Мастер-класс удален' });
    } catch (error) {
        console.error('Admin delete masterclass API error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка удаления мастер-класса: ' + error.message 
        });
    }
});

// Статические файлы и маршруты
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/index.html'));
});

app.get('/tours', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/tours.html'));
});

app.get('/exhibits', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/exhibits.html'));
});

app.get('/collections', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/collections.html'));
});

app.get('/exhibitions', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/exhibitions.html'));
});

app.get('/guides', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/guides.html'));
});

app.get('/masterclasses', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/masterclasses.html'));
});

app.get('/aut.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/aut.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/register.html'));
});

app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'museum/html/profile.html'));
});

// Обработка ошибок 404 для API
app.use('/api/*', (req, res) => {
    res.status(404).json({ success: false, message: 'API endpoint not found' });
});

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

app.listen(PORT, () => {
    console.log(`Museum server running on http://localhost:${PORT}`);
    console.log(`Database: museum`);
    console.log(`Static files served from: ${path.join(__dirname, 'museum')}`);
});